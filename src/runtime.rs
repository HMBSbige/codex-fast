//! Fast-unlock session policy, driven by CDP events from [`crate::cdp`].
//!
//! Serves patched renderer scripts through `Fetch.fulfillRequest` and verifies that the
//! page which finished loading is the one that received them. The wire protocol itself —
//! ids, pending responses, and the no-nested-events rule — lives in [`crate::cdp`].

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine as _, engine::general_purpose};
use serde_json::{Value, json};

use crate::asar::{CompatibilityPlan, path_suffixes};
use crate::cdp::{
    COMMAND_TIMEOUT, CdpCommandError, Connection, STARTUP_AUTO_ATTACH_ID, SessionHandler,
};
use crate::platform::{APP_SHUTDOWN_GRACE, AppExited, LaunchedApp, PipeTransport};
use crate::trace;

const INITIAL_RELOAD_TIMEOUT: Duration = Duration::from_secs(45);
/// Exercises the write half of the pipe, which reading alone never touches. A failure here
/// tears down the app, so the interval stays generous; exits and detaches are caught by the
/// event pump regardless.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);
const PAGE_REPLACEMENT_TIMEOUT: Duration = COMMAND_TIMEOUT;

pub struct PatchSession {
    cdp: Connection,
    session: FastSession,
}

/// Fast-unlock policy: which resources to serve, and which page is allowed to load.
struct FastSession {
    expected_resources: BTreeMap<String, ExpectedResource>,
    request_paths: BTreeMap<String, String>,
    pages: BTreeMap<String, PageState>,
    page_replacement_deadline: Option<Instant>,
}

pub struct RuntimePlan {
    expected_resources: BTreeMap<String, ExpectedResource>,
    request_paths: BTreeMap<String, String>,
}

#[derive(Debug)]
struct ExpectedResource {
    labels: Arc<str>,
    encoded_body: Arc<str>,
    required_for_ready: bool,
}

/// Which side of a script delivery an observation came from. Recording it keeps two
/// events from the same side — CDP may reuse a request id — from pairing with each other.
#[derive(Debug, Eq, PartialEq)]
enum ScriptDeliveryHalf {
    Network,
    Fulfilled,
}

#[derive(Debug)]
enum PageState {
    Configuring,
    Pending { frame_id: String },
    Intercepting(PageVerification),
}

impl PageState {
    fn is_loaded(&self) -> bool {
        matches!(self, Self::Intercepting(page) if page.is_loaded())
    }
}

#[derive(Debug, Eq, PartialEq)]
enum MainFrame {
    Transitional { frame_id: String },
    App { frame_id: String, loader_id: String },
    NonApp,
}

#[derive(Debug)]
struct PageVerification {
    frame_id: String,
    loader_id: String,
    loaded: bool,
    /// Whether the controlled reload's own load event ever fired. Unlike `loaded` this
    /// never goes back to false, so a later navigation is judged against the reload having
    /// finished once, not against whichever load is in flight now.
    ///
    /// The boundary is the load event, not `FAST_READY`: a navigation between the two is
    /// treated as a rebind. That does not let an unpatched page through, because
    /// `wait_until_fast_ready` is still holding its own deadline over the whole window and
    /// the rebind clears `verified_resources`, so the resources must arrive either way.
    first_load_completed: bool,
    /// Set when a navigation supersedes a completed load, cleared once the new one has
    /// delivered every required resource. While it is set the page is on the clock: the
    /// document now running was not proven to have received the patched scripts.
    reverify_deadline: Option<Instant>,
    verified_resources: BTreeSet<String>,
    pending_script_deliveries: BTreeMap<String, PendingHalf>,
}

#[derive(Debug)]
struct PendingHalf {
    half: ScriptDeliveryHalf,
    resource_path: String,
}

impl PageVerification {
    fn new(frame_id: String, loader_id: String) -> Self {
        Self {
            frame_id,
            loader_id,
            loaded: false,
            first_load_completed: false,
            reverify_deadline: None,
            verified_resources: BTreeSet::new(),
            pending_script_deliveries: BTreeMap::new(),
        }
    }

    fn observe_document(&mut self, frame_id: &str, loader_id: &str, url: &str) -> Result<()> {
        if frame_id != self.frame_id {
            return Ok(());
        }
        if !url.starts_with("app://") {
            bail!("controlled reload navigated to non-app document: {url}");
        }
        if loader_id != self.loader_id {
            bail!("main frame navigated again during Fast verification");
        }
        Ok(())
    }

    /// Rebinds to a navigation that committed after the controlled reload had loaded. The
    /// target is reused rather than replaced, so nothing else resets the per-navigation
    /// state.
    fn rebind_to_navigation(&mut self, loader_id: String, deadline: Instant) {
        self.loader_id = loader_id;
        self.loaded = false;
        self.reverify_deadline = Some(deadline);
        self.verified_resources.clear();
        self.pending_script_deliveries.clear();
    }

    /// Whether `loader_id` starts a navigation that supersedes the one that finished
    /// loading.
    fn supersedes_completed_load(&self, frame_id: &str, loader_id: &str) -> bool {
        self.first_load_completed && frame_id == self.frame_id && loader_id != self.loader_id
    }

    fn observe_load(&mut self, frame_id: &str, loader_id: Option<&str>) {
        if frame_id != self.frame_id {
            return;
        }
        if loader_id
            .filter(|loader_id| !loader_id.is_empty())
            .is_none_or(|loader_id| loader_id == self.loader_id)
        {
            self.loaded = true;
            self.first_load_completed = true;
        }
    }

    fn is_loaded(&self) -> bool {
        self.loaded
    }

    /// The network side is the only one carrying a loader id, which is what proves the
    /// script belongs to the navigation being verified rather than a later one.
    fn observe_script_request(
        &mut self,
        request_id: &str,
        frame_id: &str,
        loader_id: &str,
        resource_path: &str,
    ) -> bool {
        !request_id.is_empty()
            && !frame_id.is_empty()
            && !loader_id.is_empty()
            && frame_id == self.frame_id
            && loader_id == self.loader_id
            && self.pair_script_delivery(request_id, ScriptDeliveryHalf::Network, resource_path)
    }

    fn record_fulfilled_script(
        &mut self,
        network_id: &str,
        frame_id: &str,
        resource_path: &str,
    ) -> bool {
        !network_id.is_empty()
            && !frame_id.is_empty()
            && frame_id == self.frame_id
            && self.pair_script_delivery(network_id, ScriptDeliveryHalf::Fulfilled, resource_path)
    }

    /// A resource counts as delivered once both halves arrive for the same request naming
    /// the same resource; either may arrive first. Requiring one of each half is what keeps
    /// a fulfilled half from standing in for the network half that should have vouched for
    /// it — and, because [`Self::rebind_to_navigation`] empties this table, no half can
    /// survive into the navigation that follows the one it was observed in.
    ///
    /// An observation that completes no pair overwrites the slot rather than clearing it:
    /// CDP reuses a request id across a redirect chain, and clearing would strand the
    /// counterpart that follows.
    fn pair_script_delivery(
        &mut self,
        request_id: &str,
        half: ScriptDeliveryHalf,
        resource_path: &str,
    ) -> bool {
        if self
            .pending_script_deliveries
            .get(request_id)
            .is_some_and(|pending| pending.half != half && pending.resource_path == resource_path)
        {
            let pending = self
                .pending_script_deliveries
                .remove(request_id)
                .expect("matched pending script delivery");
            return self.verified_resources.insert(pending.resource_path);
        }

        self.pending_script_deliveries.insert(
            request_id.to_owned(),
            PendingHalf {
                half,
                resource_path: resource_path.to_owned(),
            },
        );
        false
    }
}

impl From<CompatibilityPlan> for RuntimePlan {
    fn from(plan: CompatibilityPlan) -> Self {
        let mut expected_resources = BTreeMap::new();
        let mut request_paths = BTreeMap::new();
        for resource in plan.resources {
            let archive_path = resource.archive_path;
            for request_path in resource.request_paths {
                request_paths.insert(request_path, archive_path.clone());
            }
            let expected = ExpectedResource {
                labels: resource
                    .labels
                    .into_iter()
                    .collect::<Vec<_>>()
                    .join("|")
                    .into(),
                encoded_body: general_purpose::STANDARD
                    .encode(resource.patched_content.as_bytes())
                    .into(),
                required_for_ready: resource.required_for_ready,
            };
            expected_resources.insert(archive_path, expected);
        }

        Self {
            expected_resources,
            request_paths,
        }
    }
}

impl PatchSession {
    pub fn new(app: LaunchedApp, transport: PipeTransport, plan: RuntimePlan) -> Self {
        Self {
            cdp: Connection::new(app, transport),
            session: FastSession {
                expected_resources: plan.expected_resources,
                request_paths: plan.request_paths,
                pages: BTreeMap::new(),
                page_replacement_deadline: None,
            },
        }
    }

    pub fn run(mut self) -> Result<()> {
        let result = self.session.run_session(&mut self.cdp);
        if let Some(exit_code) = app_exit_code(&result) {
            println!("APP_EXIT_CODE={exit_code}");
            let _ = flush_stdout();
        }
        reconcile_run(result)
    }
}

impl SessionHandler for FastSession {
    fn handle_event(&mut self, cdp: &mut Connection, event: Value) -> Result<()> {
        self.handle_message(cdp, event)
    }

    fn wait_deadline(&self, command_deadline: Instant) -> Instant {
        self.effective_deadline(command_deadline)
    }

    fn handle_wait_deadline(&mut self, app: &LaunchedApp) -> Result<()> {
        self.ensure_page_interception(app)
    }
}

impl FastSession {
    fn run_session(&mut self, cdp: &mut Connection) -> Result<()> {
        cdp.wait_response(STARTUP_AUTO_ATTACH_ID, "Target.setAutoAttach", self)?;

        println!("APP_PID={}", cdp.app().pid());
        println!("APP_IMAGE={}", cdp.app().image_path()?);
        println!("APP_IDENTITY={}", cdp.app().identity()?);
        flush_stdout()?;

        let version = cdp.send_command("Browser.getVersion", None, None, self)?;
        if let Some(product) = version.get("product").and_then(Value::as_str) {
            println!("CDP_PRODUCT={product}");
        }

        flush_stdout()?;

        self.wait_until_fast_ready(cdp)?;
        self.keep_alive(cdp)
    }

    fn wait_until_fast_ready(&mut self, cdp: &mut Connection) -> Result<()> {
        let deadline = Instant::now() + INITIAL_RELOAD_TIMEOUT;
        loop {
            if let Some(session_id) = self.loaded_page_session()
                && self.missing_resources(session_id).next().is_none()
            {
                break;
            }
            if Instant::now() >= deadline {
                let missing = self.loaded_page_session().map(|session_id| {
                    self.missing_resources(session_id)
                        .collect::<Vec<_>>()
                        .join(", ")
                });
                return abort_patch_with(
                    cdp,
                    match missing {
                        Some(missing) => anyhow!(
                            "Fast scripts were not delivered during controlled reload: {missing}"
                        ),
                        None => anyhow!(
                            "controlled Fast reload timed out before the main frame finished loading"
                        ),
                    },
                );
            }

            let wait_until = self.effective_deadline(deadline);
            cdp.pump_event(wait_until, self)?;
            self.ensure_page_interception(cdp.app())?;
        }

        println!("FAST_READY=1");
        println!("KEEP_LAUNCHER_RUNNING=1");
        flush_stdout()?;
        Ok(())
    }

    fn keep_alive(&mut self, cdp: &mut Connection) -> Result<()> {
        let mut next_heartbeat = Instant::now() + HEARTBEAT_INTERVAL;
        loop {
            if let Some(exit_code) = cdp.app().exit_code()? {
                return Err(AppExited(exit_code).into());
            }

            self.ensure_page_interception(cdp.app())?;
            let wait_until = self.effective_deadline(next_heartbeat);
            cdp.pump_event(wait_until, self)?;
            self.ensure_page_interception(cdp.app())?;

            if Instant::now() >= next_heartbeat {
                cdp.send_command("Browser.getVersion", None, None, self)
                    .context("heartbeat failed")?;
                trace(format_args!("HEARTBEAT_OK"));
                next_heartbeat = Instant::now() + HEARTBEAT_INTERVAL;
            }
        }
    }

    fn handle_message(&mut self, cdp: &mut Connection, value: Value) -> Result<()> {
        let Some(method) = value.get("method").and_then(Value::as_str) else {
            return Ok(());
        };
        trace(format_args!(
            "CDP_RECV_EVENT method={method} session={}",
            value.get("sessionId").and_then(Value::as_str).unwrap_or("")
        ));
        match self.dispatch_local_event(&value) {
            Ok(true) => return Ok(()),
            Ok(false) => {}
            Err(error) => return abort_patch_with(cdp, error),
        }
        match method {
            "Target.attachedToTarget" => self.handle_attached_to_target(cdp, &value),
            "Target.detachedFromTarget" => {
                if let Some(detached_session) = event_detaches_session(&value) {
                    self.detach_page_session(detached_session);
                }
                Ok(())
            }
            "Network.requestWillBeSent" => self.handle_network_request(&value),
            "Page.lifecycleEvent" => self.handle_page_lifecycle(&value),
            "Fetch.requestPaused" => self.handle_fetch_request_paused(cdp, &value),
            "Inspector.detached" => {
                if let Some(session_id) = event_detaches_session(&value) {
                    self.detach_page_session(session_id);
                    return Ok(());
                }
                if let Some(exit_code) = cdp.app().wait_for_exit(APP_SHUTDOWN_GRACE)? {
                    return Err(AppExited(exit_code).into());
                }
                abort_patch_with(
                    cdp,
                    anyhow!("CDP inspector detached while runtime patching was still required"),
                )
            }
            _ => Ok(()),
        }
    }

    /// Dispatches events whose state transition itself needs no CDP I/O. Fatal outcomes
    /// are returned separately so the outer handler can terminate the app first.
    fn dispatch_local_event(&mut self, value: &Value) -> Result<bool> {
        match value.get("method").and_then(Value::as_str) {
            Some("Page.frameNavigated") => self.handle_frame_navigated(value).map(|()| true),
            _ => Ok(false),
        }
    }

    fn handle_attached_to_target(&mut self, cdp: &mut Connection, value: &Value) -> Result<()> {
        let method = "Target.attachedToTarget";
        let params = require_field(value, method, "params")?;
        let session_id = required_str(params, method, "sessionId")?;
        let target = require_field(params, method, "targetInfo")?;
        let target_type = str_field(target, "type");
        let url = str_field(target, "url");
        let waiting = params
            .get("waitingForDebugger")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        if target_type != "page" || is_non_app_page_url(url) {
            if waiting {
                cdp.send_command(
                    "Runtime.runIfWaitingForDebugger",
                    None,
                    Some(session_id),
                    self,
                )?;
            }
            return Ok(());
        }
        if !waiting {
            return abort_patch_with(
                cdp,
                anyhow!("app page target executed before Fast interception was armed: {url}"),
            );
        }
        let session_id = session_id.to_owned();
        if self
            .pages
            .insert(session_id.clone(), PageState::Configuring)
            .is_some()
        {
            return abort_patch_with(cdp, anyhow!("duplicate page session {session_id}"));
        }

        cdp.send_command(
            "Fetch.enable",
            Some(json!({ "patterns": fetch_patterns(&self.request_paths) })),
            Some(&session_id),
            self,
        )?;
        let page_enable_id = cdp.start_command("Page.enable", None, Some(&session_id))?;
        let network_enable_id = cdp.start_command("Network.enable", None, Some(&session_id))?;
        let cache_disabled_id = cdp.start_command(
            "Network.setCacheDisabled",
            Some(json!({ "cacheDisabled": true })),
            Some(&session_id),
        )?;
        let lifecycle_id = cdp.start_command(
            "Page.setLifecycleEventsEnabled",
            Some(json!({ "enabled": true })),
            Some(&session_id),
        )?;
        cdp.send_command(
            "Runtime.runIfWaitingForDebugger",
            None,
            Some(&session_id),
            self,
        )?;
        cdp.wait_response(page_enable_id, "Page.enable", self)?;
        cdp.wait_response(network_enable_id, "Network.enable", self)?;
        cdp.wait_response(cache_disabled_id, "Network.setCacheDisabled", self)?;
        cdp.wait_response(lifecycle_id, "Page.setLifecycleEventsEnabled", self)?;
        let frame_tree = cdp.send_command("Page.getFrameTree", None, Some(&session_id), self)?;
        let frame = frame_tree
            .get("frameTree")
            .and_then(|tree| tree.get("frame"))
            .ok_or_else(|| anyhow!("Page.getFrameTree missing main frame"))?;
        let (frame_id, loader_id) = match classify_main_frame(frame) {
            Ok(MainFrame::Transitional { frame_id }) => (frame_id, None),
            Ok(MainFrame::App {
                frame_id,
                loader_id,
            }) => (frame_id, Some(loader_id)),
            Ok(MainFrame::NonApp) => {
                self.pages.remove(&session_id);
                return Ok(());
            }
            Err(error) => {
                return abort_patch_with(cdp, error.context("validate page main frame"));
            }
        };
        match self.pages.get_mut(&session_id) {
            Some(state @ PageState::Configuring) => {
                *state = PageState::Pending {
                    frame_id: frame_id.clone(),
                };
            }
            _ => {
                return abort_patch_with(
                    cdp,
                    anyhow!("page session {session_id} detached during Fast configuration"),
                );
            }
        }
        if let Some(loader_id) = loader_id {
            self.begin_controlled_load(&session_id, frame_id, loader_id);
        }
        Ok(())
    }

    fn handle_frame_navigated(&mut self, value: &Value) -> Result<()> {
        let Some(session_id) = value.get("sessionId").and_then(Value::as_str) else {
            return Ok(());
        };
        let Some(frame) = value.get("params").and_then(|params| params.get("frame")) else {
            return Ok(());
        };
        let Some(frame_id) = frame.get("id").and_then(Value::as_str) else {
            return Ok(());
        };
        if matches!(self.pages.get(session_id), Some(PageState::Intercepting(_))) {
            return self.commit_navigation(session_id, frame_id, frame);
        }

        let Some(PageState::Pending {
            frame_id: pending_frame_id,
        }) = self.pages.get(session_id)
        else {
            return Ok(());
        };
        if frame_id != pending_frame_id {
            return Ok(());
        }

        let frame_state = match classify_main_frame(frame) {
            Ok(MainFrame::Transitional { .. }) => return Ok(()),
            Ok(MainFrame::App {
                frame_id,
                loader_id,
            }) => (frame_id, loader_id),
            Ok(MainFrame::NonApp) => {
                self.pages.remove(session_id);
                return Ok(());
            }
            Err(error) => {
                return Err(error.context("validate committed page main frame"));
            }
        };
        self.begin_controlled_load(session_id, frame_state.0, frame_state.1);
        Ok(())
    }

    fn begin_controlled_load(&mut self, session_id: &str, frame_id: String, loader_id: String) {
        debug_assert!(matches!(
            self.pages.get(session_id),
            Some(PageState::Pending {
                frame_id: pending_frame_id,
            }) if pending_frame_id == &frame_id
        ));

        self.pages.insert(
            session_id.to_owned(),
            PageState::Intercepting(PageVerification::new(frame_id, loader_id)),
        );
        self.page_replacement_deadline = None;
    }

    fn detach_page_session(&mut self, session_id: &str) {
        if self.pages.remove(session_id).is_some() && self.pages.is_empty() {
            self.page_replacement_deadline = Some(Instant::now() + PAGE_REPLACEMENT_TIMEOUT);
        }
    }

    fn session_detached_or_pending(&self, cdp: &Connection, session_id: &str) -> bool {
        !self.pages.contains_key(session_id)
            || cdp.queued_events().any(|event| {
                event_detaches_session(event).is_some_and(|detached| detached == session_id)
            })
    }

    /// Handles a navigation that has actually committed in an intercepting page.
    ///
    /// This is the only place the per-navigation state is torn down. `requestWillBeSent`
    /// merely announces an attempt — it can still be cancelled, fail, or answer 204, all of
    /// which leave the current document in place — so acting on it would discard the
    /// verification of a page that is still running.
    ///
    /// Committing after the controlled reload completed is the app routing itself, not a
    /// breach: interception is still armed, so the new document gets patched scripts too.
    /// It is re-gated rather than trusted — until it has been proven to have received them,
    /// the document on screen is one whose scripts were never checked. Committing *during*
    /// the controlled reload is a breach, and is refused the same way the network path
    /// refuses it.
    fn commit_navigation(&mut self, session_id: &str, frame_id: &str, frame: &Value) -> Result<()> {
        let loader_id = str_field(frame, "loaderId");
        let url = str_field(frame, "url");
        let Some(PageState::Intercepting(page)) = self.pages.get_mut(session_id) else {
            return Ok(());
        };
        if loader_id.is_empty() || frame_id != page.frame_id || loader_id == page.loader_id {
            return Ok(());
        }
        if !page.first_load_completed {
            return page.observe_document(frame_id, loader_id, url);
        }
        if is_non_app_page_url(url) {
            bail!("app page navigated to a non-app document: {url}");
        }
        trace(format_args!(
            "PAGE_RENAVIGATED session={session_id} loader={loader_id}"
        ));
        page.rebind_to_navigation(
            loader_id.to_owned(),
            Instant::now() + INITIAL_RELOAD_TIMEOUT,
        );
        Ok(())
    }

    fn handle_network_request(&mut self, value: &Value) -> Result<()> {
        let method = "Network.requestWillBeSent";
        let Some(session_id) = value.get("sessionId").and_then(Value::as_str) else {
            return Ok(());
        };
        let params = require_field(value, method, "params")?;
        let frame_id = str_field(params, "frameId");
        let loader_id = str_field(params, "loaderId");
        let url = request_url(params, method)?;
        match params.get("type").and_then(Value::as_str) {
            Some("Document") => {
                let Some(PageState::Intercepting(page)) = self.pages.get_mut(session_id) else {
                    return Ok(());
                };
                if loader_id.is_empty() {
                    bail!("main document request missing loaderId");
                }
                // A request is not a commit. The navigation may still be cancelled, fail,
                // or answer 204, leaving the current document in place — so nothing
                // destructive happens here. `Page.frameNavigated` is the commit point.
                if page.supersedes_completed_load(frame_id, loader_id) {
                    trace(format_args!(
                        "PAGE_RENAVIGATION_STARTED session={session_id} loader={loader_id}"
                    ));
                    return Ok(());
                }
                page.observe_document(frame_id, loader_id, url)
            }
            Some("Script") => {
                let Some(resource_path) = normalize_app_resource(url, &self.request_paths) else {
                    return Ok(());
                };
                let request_id = required_str(params, method, "requestId")?;
                if let Some(PageState::Intercepting(page)) = self.pages.get_mut(session_id)
                    && page.observe_script_request(request_id, frame_id, loader_id, &resource_path)
                {
                    trace(format_args!(
                        "SCRIPT_DELIVERY_VERIFIED session={session_id} loader={loader_id} resource={resource_path}"
                    ));
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn handle_page_lifecycle(&mut self, value: &Value) -> Result<()> {
        let Some(session_id) = value.get("sessionId").and_then(Value::as_str) else {
            return Ok(());
        };
        let Some(PageState::Intercepting(page)) = self.pages.get_mut(session_id) else {
            return Ok(());
        };
        if page.is_loaded() {
            return Ok(());
        }
        let Some(params) = value.get("params") else {
            return Ok(());
        };
        if params.get("name").and_then(Value::as_str) != Some("load") {
            return Ok(());
        }
        page.observe_load(
            str_field(params, "frameId"),
            params.get("loaderId").and_then(Value::as_str),
        );
        Ok(())
    }

    fn handle_fetch_request_paused(&mut self, cdp: &mut Connection, value: &Value) -> Result<()> {
        let method = "Fetch.requestPaused";
        let session_id = value.get("sessionId").and_then(Value::as_str);
        let params = require_field(value, method, "params")?;
        let request_id = required_str(params, method, "requestId")?;
        let url = request_url(params, method)?;

        let Some(resource_path) = normalize_app_resource(url, &self.request_paths) else {
            self.continue_request(cdp, request_id, session_id)?;
            return Ok(());
        };
        if session_id.is_none_or(|session_id| !self.pages.contains_key(session_id)) {
            self.continue_request(cdp, request_id, session_id)?;
            return Ok(());
        }
        if !is_request_stage(params) {
            return abort_patch_with(
                cdp,
                anyhow!("planned Fast resource was intercepted outside Request stage: {url}"),
            );
        }
        let page_loaded = session_id
            .is_some_and(|session_id| self.pages.get(session_id).is_some_and(PageState::is_loaded));
        let script_request = params.get("resourceType").and_then(Value::as_str) == Some("Script");
        let network_id = str_field(params, "networkId");
        let frame_id = str_field(params, "frameId");
        // A miss is unreachable today: `normalize_app_resource` maps through
        // `request_paths`, whose values are the `expected_resources` keys. Continuing
        // rather than unwrapping keeps a future planner change from hanging the renderer
        // on a request nobody answers.
        let Some((labels, encoded_body)) =
            self.expected_resources.get(&resource_path).map(|expected| {
                (
                    Arc::clone(&expected.labels),
                    Arc::clone(&expected.encoded_body),
                )
            })
        else {
            self.continue_request(cdp, request_id, session_id)?;
            return Ok(());
        };
        // The ASAR snapshot and patched bytes were verified immediately before launch.
        // Fulfill the request before the app protocol can deliver the original bytes.
        let delivery = self.fulfill_request(cdp, request_id, &encoded_body, session_id);
        if let Err(error) = delivery {
            let session_detached = session_id
                .is_some_and(|session_id| self.session_detached_or_pending(cdp, session_id));
            if is_stale_interception_error(&error, page_loaded, session_detached) {
                trace(format_args!(
                    "STALE_INTERCEPTION request={request_id} session={}",
                    session_id.unwrap_or("")
                ));
                return Ok(());
            }
            return Err(error);
        }

        if script_request
            && let Some(session_id) = session_id
            && let Some(PageState::Intercepting(page)) = self.pages.get_mut(session_id)
            && page.record_fulfilled_script(network_id, frame_id, &resource_path)
        {
            trace(format_args!(
                "SCRIPT_DELIVERY_VERIFIED session={session_id} resource={resource_path}"
            ));
        }

        println!("PATCHED_RESOURCE={} LABELS={}", resource_path, labels);
        flush_stdout()?;
        Ok(())
    }

    fn continue_request(
        &mut self,
        cdp: &mut Connection,
        request_id: &str,
        session_id: Option<&str>,
    ) -> Result<()> {
        cdp.send_command(
            "Fetch.continueRequest",
            Some(json!({ "requestId": request_id })),
            session_id,
            self,
        )?;
        Ok(())
    }

    fn fulfill_request(
        &mut self,
        cdp: &mut Connection,
        request_id: &str,
        encoded_body: &str,
        session_id: Option<&str>,
    ) -> Result<()> {
        cdp.send_command(
            "Fetch.fulfillRequest",
            Some(json!({
                "requestId": request_id,
                "responseCode": 200,
                "responseHeaders": [{
                    "name": "content-type",
                    "value": "application/javascript; charset=utf-8"
                }],
                "body": encoded_body
            })),
            session_id,
            self,
        )?;
        Ok(())
    }

    fn loaded_page_session(&self) -> Option<&str> {
        self.pages
            .iter()
            .find_map(|(session_id, page)| page.is_loaded().then_some(session_id.as_str()))
    }

    fn missing_resources<'a>(&'a self, session_id: &str) -> impl Iterator<Item = &'a str> {
        let verified = match self.pages.get(session_id) {
            Some(PageState::Intercepting(page)) => Some(&page.verified_resources),
            _ => None,
        };
        missing_required_resources(&self.expected_resources, verified)
    }

    /// Re-gates a page that navigated after its controlled reload completed. The new
    /// document is running scripts we have not proven were patched, so it gets the same
    /// deadline the first load did and the same treatment on expiry.
    fn ensure_renavigated_pages_verified(&mut self, app: &LaunchedApp) -> Result<()> {
        match self.settle_reverification_gates() {
            Some(missing) => abort_patch_with_app(
                app,
                anyhow!(
                    "page navigated after its completed load and did not receive the Fast scripts again: {missing}"
                ),
            ),
            None => Ok(()),
        }
    }

    /// Lifts the gate from every rebound page that has since delivered everything required.
    /// Returns the missing resources of the first page whose deadline has passed.
    fn settle_reverification_gates(&mut self) -> Option<String> {
        let now = Instant::now();
        let expected_resources = &self.expected_resources;
        for state in self.pages.values_mut() {
            let PageState::Intercepting(page) = state else {
                continue;
            };
            let Some(deadline) = page.reverify_deadline else {
                continue;
            };
            let missing =
                missing_required_resources(expected_resources, Some(&page.verified_resources))
                    .next()
                    .is_some();
            if !missing {
                page.reverify_deadline = None;
            } else if now >= deadline {
                return Some(
                    missing_required_resources(expected_resources, Some(&page.verified_resources))
                        .collect::<Vec<_>>()
                        .join(", "),
                );
            }
        }
        None
    }

    fn ensure_page_interception(&mut self, app: &LaunchedApp) -> Result<()> {
        self.ensure_renavigated_pages_verified(app)?;
        if self
            .page_replacement_deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return abort_patch_with_app(
                app,
                anyhow!(
                    "active page target was not replaced; Fast interception is no longer active"
                ),
            );
        }
        Ok(())
    }

    /// The soonest instant the pump must return by, so that no deadline is slept through.
    fn effective_deadline(&self, deadline: Instant) -> Instant {
        self.pages
            .values()
            .filter_map(|page| match page {
                PageState::Intercepting(page) => page.reverify_deadline,
                _ => None,
            })
            .chain(self.page_replacement_deadline)
            .fold(deadline, Instant::min)
    }
}

/// Kills the app, then surfaces `error`. An interception-gated page must not keep running
/// once Fast verification fails — it would carry on with the original, unpatched scripts.
fn abort_patch_with<T>(cdp: &Connection, error: anyhow::Error) -> Result<T> {
    abort_patch_with_app(cdp.app(), error)
}

fn abort_patch_with_app<T>(app: &LaunchedApp, error: anyhow::Error) -> Result<T> {
    app.abort_patch();
    Err(error)
}

fn classify_main_frame(frame: &Value) -> Result<MainFrame> {
    let frame_id = required_str(frame, "page main frame", "id")?.to_owned();
    let url = required_str(frame, "page main frame", "url")?;
    if is_transitional_page_url(url) {
        return Ok(MainFrame::Transitional { frame_id });
    }
    if !url.starts_with("app://") {
        return Ok(MainFrame::NonApp);
    }
    let loader_id = frame
        .get("loaderId")
        .and_then(Value::as_str)
        .filter(|loader_id| !loader_id.is_empty())
        .ok_or_else(|| anyhow!("app main frame missing loader id"))?
        .to_owned();
    Ok(MainFrame::App {
        frame_id,
        loader_id,
    })
}

fn is_transitional_page_url(url: &str) -> bool {
    url.is_empty() || url == "about:blank"
}

fn is_non_app_page_url(url: &str) -> bool {
    !is_transitional_page_url(url) && !url.starts_with("app://")
}

fn app_exit_code(result: &Result<()>) -> Option<u32> {
    result
        .as_ref()
        .err()
        .and_then(|error| error.downcast_ref::<AppExited>())
        .map(|exit| exit.0)
}

fn reconcile_run(result: Result<()>) -> Result<()> {
    if app_exit_code(&result) == Some(0) {
        Ok(())
    } else {
        result
    }
}

fn fetch_patterns(request_paths: &BTreeMap<String, String>) -> Vec<Value> {
    request_paths
        .keys()
        .flat_map(|path| {
            let base = format!("app://*/{path}");
            [
                json!({ "urlPattern": base, "requestStage": "Request" }),
                json!({
                    "urlPattern": format!("{base}\\?*"),
                    "requestStage": "Request"
                }),
            ]
        })
        .collect()
}

fn normalize_app_resource(url: &str, request_paths: &BTreeMap<String, String>) -> Option<String> {
    let rest = url.strip_prefix("app://")?;
    let (_, path_with_query) = rest.split_once('/').unwrap_or((rest, ""));
    let request_path = path_with_query
        .split(['?', '#'])
        .next()
        .unwrap_or_default()
        .trim_matches('/');
    path_suffixes(request_path).find_map(|suffix| request_paths.get(suffix).cloned())
}

fn is_request_stage(params: &Value) -> bool {
    params.get("responseStatusCode").is_none() && params.get("responseErrorReason").is_none()
}

fn require_field<'a>(node: &'a Value, method: &str, key: &str) -> Result<&'a Value> {
    node.get(key)
        .ok_or_else(|| anyhow!("{method} missing {key}"))
}

fn required_str<'a>(node: &'a Value, method: &str, key: &str) -> Result<&'a str> {
    node.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("{method} missing {key}"))
}

fn str_field<'a>(node: &'a Value, key: &str) -> &'a str {
    node.get(key).and_then(Value::as_str).unwrap_or_default()
}

fn request_url<'a>(params: &'a Value, method: &str) -> Result<&'a str> {
    params
        .get("request")
        .and_then(|request| request.get("url"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("{method} missing request.url"))
}

fn missing_required_resources<'a>(
    expected_resources: &'a BTreeMap<String, ExpectedResource>,
    verified: Option<&'a BTreeSet<String>>,
) -> impl Iterator<Item = &'a str> {
    expected_resources
        .iter()
        .filter(|(_, resource)| resource.required_for_ready)
        .map(|(path, _)| path.as_str())
        .filter(move |path| verified.is_none_or(|verified| !verified.contains(*path)))
}

fn event_detaches_session(event: &Value) -> Option<&str> {
    match event.get("method").and_then(Value::as_str) {
        Some("Target.detachedFromTarget") => event
            .get("params")
            .and_then(|params| params.get("sessionId"))
            .and_then(Value::as_str),
        Some("Inspector.detached") => event.get("sessionId").and_then(Value::as_str),
        _ => None,
    }
}

fn is_stale_interception_error(
    error: &anyhow::Error,
    page_loaded: bool,
    session_detached: bool,
) -> bool {
    let Some(error) = error.downcast_ref::<CdpCommandError>() else {
        return false;
    };
    if !matches!(
        error.method(),
        "Fetch.fulfillRequest" | "Fetch.continueRequest"
    ) {
        return false;
    }

    let code = error.details().get("code").and_then(Value::as_i64);
    let message = error.details().get("message").and_then(Value::as_str);
    let stale_request = !page_loaded
        && code == Some(-32602)
        && message.is_some_and(|message| message.trim_end_matches('.') == "Invalid InterceptionId");
    let stale_session = session_detached
        && code == Some(-32001)
        && message == Some("Session with given id not found.");
    stale_request || stale_session
}

fn flush_stdout() -> Result<()> {
    io::stdout().flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asar::is_safe_request_path;
    use crate::cdp::response_result;

    fn page_verification() -> PageVerification {
        PageVerification::new("frame".to_owned(), "new".to_owned())
    }

    #[test]
    fn requires_the_active_page_loader_to_finish_loading() {
        let mut page = page_verification();
        page.observe_load("other-frame", Some("new"));
        assert!(!page.is_loaded());

        page.observe_load("frame", Some("other"));
        assert!(!page.is_loaded());

        page.observe_load("frame", Some("new"));
        assert!(page.is_loaded());

        let mut page = page_verification();
        page.observe_load("frame", None);
        assert!(page.is_loaded());
    }

    #[test]
    fn rejects_navigation_away_from_the_active_app_page() {
        let mut page = page_verification();
        page.observe_document("frame", "new", "app://codex/index.html")
            .unwrap();
        assert!(
            page.observe_document("frame", "other", "app://codex/index.html")
                .is_err()
        );

        let mut page = page_verification();
        assert!(
            page.observe_document("frame", "new", "https://example.com/")
                .is_err()
        );
    }

    #[test]
    fn waits_for_an_app_document_before_configuring_a_new_page() {
        assert_eq!(
            classify_main_frame(&json!({
                "id": "frame",
                "url": "about:blank",
                "loaderId": ""
            }))
            .unwrap(),
            MainFrame::Transitional {
                frame_id: "frame".to_owned()
            }
        );
        assert_eq!(
            classify_main_frame(&json!({
                "id": "frame",
                "url": "",
                "loaderId": ""
            }))
            .unwrap(),
            MainFrame::Transitional {
                frame_id: "frame".to_owned()
            }
        );
        assert_eq!(
            classify_main_frame(&json!({
                "id": "frame",
                "url": "app://codex/index.html",
                "loaderId": "loader"
            }))
            .unwrap(),
            MainFrame::App {
                frame_id: "frame".to_owned(),
                loader_id: "loader".to_owned(),
            }
        );
        assert_eq!(
            classify_main_frame(&json!({
                "id": "frame",
                "url": "https://example.com/",
                "loaderId": "loader"
            }))
            .unwrap(),
            MainFrame::NonApp
        );
    }

    #[test]
    fn ignores_only_stale_interception_ids_before_page_load() {
        for method in ["Fetch.fulfillRequest", "Fetch.continueRequest"] {
            let error = response_result(
                json!({
                    "error": {
                        "code": -32602,
                        "message": "Invalid InterceptionId."
                    }
                }),
                method,
            )
            .unwrap_err();

            assert!(is_stale_interception_error(&error, false, false));
            assert!(!is_stale_interception_error(&error, true, false));
        }

        let stale_session = response_result(
            json!({
                "error": {
                    "code": -32001,
                    "message": "Session with given id not found."
                }
            }),
            "Fetch.fulfillRequest",
        )
        .unwrap_err();
        assert!(is_stale_interception_error(&stale_session, false, true));
        assert!(!is_stale_interception_error(&stale_session, false, false));

        let unrelated = response_result(
            json!({
                "error": {
                    "code": -32602,
                    "message": "Invalid InterceptionId."
                }
            }),
            "Runtime.evaluate",
        )
        .unwrap_err();
        assert!(!is_stale_interception_error(&unrelated, false, true));
    }

    #[test]
    fn fetch_patterns_target_only_exact_resource_suffixes() {
        let request_paths = BTreeMap::from([
            (
                "assets/settings-abc.js".to_owned(),
                "assets/settings-abc.js".to_owned(),
            ),
            (
                "webview/assets/settings-abc.js".to_owned(),
                "assets/settings-abc.js".to_owned(),
            ),
        ]);
        let fetch_patterns = fetch_patterns(&request_paths);
        assert!(
            fetch_patterns
                .iter()
                .all(|value| value["requestStage"] == "Request")
        );
        let patterns = fetch_patterns
            .into_iter()
            .map(|value| value["urlPattern"].as_str().unwrap().to_owned())
            .collect::<BTreeSet<_>>();

        assert_eq!(
            patterns,
            BTreeSet::from([
                "app://*/assets/settings-abc.js".to_owned(),
                "app://*/assets/settings-abc.js\\?*".to_owned(),
                "app://*/webview/assets/settings-abc.js".to_owned(),
                "app://*/webview/assets/settings-abc.js\\?*".to_owned(),
            ])
        );
        assert!(patterns.iter().all(|pattern| !pattern.ends_with(".js*")));
    }

    #[test]
    fn readiness_requires_core_resources_but_not_lazy_ui_resources() {
        let expected = BTreeMap::from([
            (
                "core.js".to_owned(),
                ExpectedResource {
                    labels: Arc::from("Core"),
                    encoded_body: Arc::from(""),
                    required_for_ready: true,
                },
            ),
            (
                "settings.js".to_owned(),
                ExpectedResource {
                    labels: Arc::from("Settings"),
                    encoded_body: Arc::from(""),
                    required_for_ready: false,
                },
            ),
        ]);

        assert_eq!(
            missing_required_resources(&expected, None).collect::<Vec<_>>(),
            vec!["core.js"]
        );
        assert!(
            missing_required_resources(&expected, Some(&BTreeSet::from(["core.js".to_owned()])))
                .next()
                .is_none()
        );
    }

    #[test]
    fn verifies_only_matching_script_halves_from_the_active_page() {
        let mut network_first = page_verification();
        assert!(!network_first.observe_script_request("request", "frame", "new", "assets/app.js"));
        assert!(network_first.record_fulfilled_script("request", "frame", "assets/app.js"));
        assert!(network_first.verified_resources.contains("assets/app.js"));

        let mut fetch_first = page_verification();
        assert!(!fetch_first.record_fulfilled_script("request", "frame", "assets/app.js"));
        assert!(fetch_first.observe_script_request("request", "frame", "new", "assets/app.js"));
        assert!(fetch_first.verified_resources.contains("assets/app.js"));

        for (network_frame, loader, network_resource, fulfilled_frame, fulfilled_resource) in [
            ("other", "new", "assets/app.js", "frame", "assets/app.js"),
            ("frame", "old", "assets/app.js", "frame", "assets/app.js"),
            ("frame", "new", "assets/app.js", "other", "assets/app.js"),
            ("frame", "new", "assets/app.js", "frame", "assets/other.js"),
        ] {
            let mut mismatch = page_verification();
            mismatch.observe_script_request("request", network_frame, loader, network_resource);
            assert!(!mismatch.record_fulfilled_script(
                "request",
                fulfilled_frame,
                fulfilled_resource
            ));
            assert!(mismatch.verified_resources.is_empty());
        }
    }

    fn intercepting_session(page: PageVerification) -> FastSession {
        FastSession {
            expected_resources: BTreeMap::from([(
                "assets/app.js".to_owned(),
                ExpectedResource {
                    labels: "Fast".into(),
                    encoded_body: "".into(),
                    required_for_ready: true,
                },
            )]),
            request_paths: BTreeMap::from([(
                "assets/app.js".to_owned(),
                "assets/app.js".to_owned(),
            )]),
            pages: BTreeMap::from([("page".to_owned(), PageState::Intercepting(page))]),
            page_replacement_deadline: None,
        }
    }

    fn document_event(loader_id: &str, url: &str) -> Value {
        json!({
            "sessionId": "page",
            "params": {
                "type": "Document",
                "frameId": "frame",
                "loaderId": loader_id,
                "request": { "url": url },
            }
        })
    }

    /// A commit that never hit the network: the only signal is `Page.frameNavigated`.
    fn frame_navigated_event(loader_id: &str, url: &str) -> Value {
        json!({
            "method": "Page.frameNavigated",
            "sessionId": "page",
            "params": {
                "frame": { "id": "frame", "loaderId": loader_id, "url": url }
            }
        })
    }

    fn intercepting_page(session: &FastSession) -> &PageVerification {
        match session.pages.get("page") {
            Some(PageState::Intercepting(page)) => page,
            _ => panic!("expected an intercepting page"),
        }
    }

    fn completed_load_page() -> PageVerification {
        let mut page = page_verification();
        page.observe_load("frame", Some("new"));
        page
    }

    fn dispatch_frame_navigated(session: &mut FastSession, event: &Value) -> Result<()> {
        if session.dispatch_local_event(event)? {
            Ok(())
        } else {
            bail!("frameNavigated event was not dispatched")
        }
    }

    #[test]
    fn does_not_dispatch_a_frame_payload_under_another_method() {
        let mut session = intercepting_session(completed_load_page());
        let mut event = frame_navigated_event("newer", "app://codex/index.html");
        event["method"] = Value::from("Page.frameStartedLoading");

        let error = dispatch_frame_navigated(&mut session, &event).unwrap_err();

        assert_eq!(error.to_string(), "frameNavigated event was not dispatched");
        assert_eq!(intercepting_page(&session).loader_id, "new");
    }

    #[test]
    fn leaves_the_loaded_page_alone_until_the_navigation_commits() {
        let mut page = completed_load_page();
        page.observe_script_request("request", "frame", "new", "assets/app.js");
        page.record_fulfilled_script("request", "frame", "assets/app.js");
        let mut session = intercepting_session(page);

        session
            .handle_network_request(&document_event("newer", "app://codex/index.html"))
            .unwrap();

        let page = intercepting_page(&session);
        assert_eq!(page.loader_id, "new");
        assert!(page.loaded);
        assert!(page.verified_resources.contains("assets/app.js"));
        assert!(page.reverify_deadline.is_none());
    }

    #[test]
    fn rebinds_once_a_navigation_after_the_first_load_completes() {
        let mut page = completed_load_page();
        page.observe_script_request("stale", "frame", "new", "assets/app.js");
        page.record_fulfilled_script("stale", "frame", "assets/app.js");
        assert_eq!(page.verified_resources.len(), 1);
        let mut session = intercepting_session(page);

        dispatch_frame_navigated(
            &mut session,
            &frame_navigated_event("newer", "app://codex/index.html"),
        )
        .unwrap();

        let page = intercepting_page(&session);
        assert_eq!(page.loader_id, "newer");
        assert!(!page.loaded);
        assert!(page.verified_resources.is_empty());
        assert!(page.pending_script_deliveries.is_empty());
        assert!(page.reverify_deadline.is_some());

        // Committing again before the rebound load completes is not a breach either.
        dispatch_frame_navigated(
            &mut session,
            &frame_navigated_event("newest", "app://codex/index.html"),
        )
        .unwrap();
        assert_eq!(intercepting_page(&session).loader_id, "newest");
    }

    #[test]
    fn rejects_a_commit_that_interrupts_the_controlled_reload() {
        // The network path refuses this as a breach; the commit path must agree rather
        // than let it through to be noticed only when the startup deadline expires.
        let mut session = intercepting_session(page_verification());

        let error = dispatch_frame_navigated(
            &mut session,
            &frame_navigated_event("newer", "app://codex/index.html"),
        )
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("main frame navigated again during Fast verification")
        );
    }

    #[test]
    fn rejects_an_about_blank_commit_during_the_controlled_reload() {
        let mut session = intercepting_session(page_verification());

        let error =
            dispatch_frame_navigated(&mut session, &frame_navigated_event("newer", "about:blank"))
                .unwrap_err();

        assert!(error.to_string().contains("non-app document"));
    }

    #[test]
    fn regates_a_committed_about_blank_document() {
        let mut page = completed_load_page();
        page.observe_script_request("stale", "frame", "new", "assets/app.js");
        page.record_fulfilled_script("stale", "frame", "assets/app.js");
        page.observe_script_request("pending", "frame", "new", "assets/app.js");
        let mut session = intercepting_session(page);

        dispatch_frame_navigated(&mut session, &frame_navigated_event("newer", "about:blank"))
            .unwrap();

        let page = intercepting_page(&session);
        assert_eq!(page.loader_id, "newer");
        assert!(!page.loaded);
        assert!(page.first_load_completed);
        assert!(page.verified_resources.is_empty());
        assert!(page.pending_script_deliveries.is_empty());
        assert!(page.reverify_deadline.is_some());
    }

    #[test]
    fn refuses_to_verify_from_a_half_that_outlived_its_navigation() {
        // The fulfilled half for a superseded navigation arrives after the rebind cleared
        // the table, so it re-inserts itself. On its own it proves nothing about the
        // navigation now in progress: that one must still make the request itself.
        let mut page = completed_load_page();
        page.observe_script_request("shared", "frame", "new", "assets/app.js");
        page.rebind_to_navigation("newer".to_owned(), Instant::now() + INITIAL_RELOAD_TIMEOUT);

        assert!(!page.record_fulfilled_script("shared", "frame", "assets/app.js"));
        assert!(page.verified_resources.is_empty());

        // Nothing else happens. The stranded half must never mature into a verification.
        page.record_fulfilled_script("other", "frame", "assets/app.js");
        assert!(page.verified_resources.is_empty());
    }

    #[test]
    fn verifies_a_resource_the_rebound_navigation_actually_requested() {
        let mut page = completed_load_page();
        page.rebind_to_navigation("newer".to_owned(), Instant::now() + INITIAL_RELOAD_TIMEOUT);

        assert!(!page.observe_script_request("request", "frame", "newer", "assets/app.js"));
        assert!(page.record_fulfilled_script("request", "frame", "assets/app.js"));
        assert!(page.verified_resources.contains("assets/app.js"));
    }

    #[test]
    fn rejects_a_request_that_interrupts_the_controlled_reload() {
        let mut session = intercepting_session(page_verification());

        // The first load never completed, so a new loader is a breach, not a rebind.
        let error = session
            .handle_network_request(&document_event("newer", "app://codex/index.html"))
            .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("main frame navigated again during Fast verification")
        );
    }

    #[test]
    fn rejects_a_non_app_commit_after_the_first_load_completes() {
        let mut session = intercepting_session(completed_load_page());

        let error = dispatch_frame_navigated(
            &mut session,
            &frame_navigated_event("newer", "https://example.com/"),
        )
        .unwrap_err();

        assert!(error.to_string().contains("non-app document"));
    }

    #[test]
    fn clears_the_reverification_gate_once_required_resources_arrive() {
        let mut page = completed_load_page();
        page.rebind_to_navigation("newer".to_owned(), Instant::now() + INITIAL_RELOAD_TIMEOUT);
        page.observe_script_request("request", "frame", "newer", "assets/app.js");
        page.record_fulfilled_script("request", "frame", "assets/app.js");
        let mut session = intercepting_session(page);

        assert!(session.settle_reverification_gates().is_none());

        assert!(intercepting_page(&session).reverify_deadline.is_none());
    }

    #[test]
    fn keeps_the_reverification_gate_while_a_resource_is_missing() {
        let mut page = completed_load_page();
        page.rebind_to_navigation("newer".to_owned(), Instant::now() + INITIAL_RELOAD_TIMEOUT);
        let mut session = intercepting_session(page);

        assert!(session.settle_reverification_gates().is_none());

        assert!(intercepting_page(&session).reverify_deadline.is_some());
    }

    #[test]
    fn reports_the_resources_a_rebound_page_never_received() {
        // The gate has expired and the page still has not been proven to be running
        // patched scripts. This is what turns into `abort_patch` in the event loop.
        let mut page = completed_load_page();
        page.rebind_to_navigation("newer".to_owned(), Instant::now() - Duration::from_secs(1));
        let mut session = intercepting_session(page);

        assert_eq!(
            session.settle_reverification_gates(),
            Some("assets/app.js".to_owned())
        );
    }

    #[test]
    fn does_not_report_a_page_that_delivered_before_its_gate_expired() {
        let mut page = completed_load_page();
        page.rebind_to_navigation("newer".to_owned(), Instant::now() - Duration::from_secs(1));
        page.observe_script_request("request", "frame", "newer", "assets/app.js");
        page.record_fulfilled_script("request", "frame", "assets/app.js");
        let mut session = intercepting_session(page);

        assert!(session.settle_reverification_gates().is_none());
        assert!(intercepting_page(&session).reverify_deadline.is_none());
    }

    #[test]
    fn waits_no_longer_than_the_soonest_deadline() {
        // The event pump must wake for a reverification gate, or the gate is only noticed
        // whenever the next event happens to arrive.
        let far = Instant::now() + Duration::from_secs(600);
        let gate = Instant::now() + Duration::from_secs(5);

        let mut page = completed_load_page();
        page.rebind_to_navigation("newer".to_owned(), gate);
        let session = intercepting_session(page);

        assert_eq!(session.effective_deadline(far), gate);

        let mut session = session;
        session.page_replacement_deadline = Some(Instant::now() + Duration::from_secs(1));
        assert_eq!(
            session.effective_deadline(far),
            session.page_replacement_deadline.unwrap()
        );
    }

    #[test]
    fn pairs_a_delivery_seen_twice_from_the_same_side() {
        let mut repeated_network = page_verification();
        repeated_network.observe_script_request("request", "frame", "new", "assets/app.js");
        repeated_network.observe_script_request("request", "frame", "new", "assets/app.js");
        assert!(repeated_network.record_fulfilled_script("request", "frame", "assets/app.js"));

        let mut repeated_fulfilled = page_verification();
        repeated_fulfilled.record_fulfilled_script("request", "frame", "assets/app.js");
        repeated_fulfilled.record_fulfilled_script("request", "frame", "assets/app.js");
        assert!(repeated_fulfilled.observe_script_request(
            "request",
            "frame",
            "new",
            "assets/app.js"
        ));
    }

    #[test]
    fn reuses_a_request_id_without_crediting_the_resource_it_abandoned() {
        let mut page = page_verification();
        page.observe_script_request("request", "frame", "new", "assets/app.js");
        page.record_fulfilled_script("request", "frame", "assets/other.js");
        assert!(page.observe_script_request("request", "frame", "new", "assets/other.js"));

        assert_eq!(
            page.verified_resources,
            BTreeSet::from(["assets/other.js".to_owned()])
        );
    }

    #[test]
    fn normalizes_planned_aliases_without_hard_coding_the_renderer_root() {
        let request_paths = BTreeMap::from([
            ("assets/chunk.js".to_owned(), "assets/chunk.js".to_owned()),
            (
                "future-root/assets/chunk.js".to_owned(),
                "assets/chunk.js".to_owned(),
            ),
        ]);

        let direct =
            normalize_app_resource("app://codex/assets/chunk.js?cache=1", &request_paths).unwrap();
        let rooted =
            normalize_app_resource("app://codex/future-root/assets/chunk.js", &request_paths)
                .unwrap();
        let prefixed = normalize_app_resource(
            "app://codex/unknown-root/future-root/assets/chunk.js",
            &request_paths,
        )
        .unwrap();

        assert_eq!(direct, "assets/chunk.js");
        assert_eq!(rooted, "assets/chunk.js");
        assert_eq!(prefixed, "assets/chunk.js");
        assert!(normalize_app_resource("app://codex/assets/other.js", &request_paths).is_none());
    }

    #[test]
    fn prefers_the_longest_matching_resource_alias() {
        let request_paths = BTreeMap::from([
            ("assets/shared.js".to_owned(), "resource-a".to_owned()),
            ("shared.js".to_owned(), "resource-b".to_owned()),
        ]);

        assert_eq!(
            normalize_app_resource("app://codex/assets/shared.js", &request_paths).unwrap(),
            "resource-a"
        );
        assert_eq!(
            normalize_app_resource("app://codex/other/shared.js", &request_paths).unwrap(),
            "resource-b"
        );
    }

    #[test]
    fn accepts_only_request_paths_with_stable_url_serialization() {
        assert!(is_safe_request_path(".vite/build/@scope/chunk_A-1.js"));
        assert!(!is_safe_request_path("assets/chunk name.js"));
        assert!(!is_safe_request_path("assets/chunk?.js"));
        assert!(!is_safe_request_path("assets/chunk*.js"));
        assert!(!is_safe_request_path("/assets/chunk.js"));
        assert!(!is_safe_request_path("assets//chunk.js"));
        assert!(!is_safe_request_path("assets/../chunk.js"));
    }
}
