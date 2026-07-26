#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

mod asar;
mod cdp;
mod js_tokens;
mod patch;
mod platform;
mod runtime;
mod token_match;

use std::ffi::{OsStr, OsString};

use anyhow::{Result, bail};

use crate::asar::{CompatibilityPlan, plan_patches, verify_plan_snapshots};
use crate::cdp::startup_auto_attach_frame;
use crate::patch::PatchStatus;
use crate::platform::{
    AppAlreadyRunning, CodexInstall, DialogKind, acquire_launcher_guard, discover_codex_install,
    enable_debug_console, is_codex_app_running, launch_codex_with_pipe, show_dialog,
};
use crate::runtime::{PatchSession, RuntimePlan};

pub(crate) fn trace(line: std::fmt::Arguments<'_>) {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    if *ENABLED.get_or_init(|| std::env::var_os("CODEX_FAST_TRACE").is_some()) {
        eprintln!("{line}");
    }
}

#[derive(Debug, Default, Eq, PartialEq)]
struct Options {
    debug: bool,
    scan_only: bool,
}

impl Options {
    fn parse(args: impl IntoIterator<Item = OsString>) -> Self {
        let mut options = Self::default();
        for arg in args {
            if arg == OsStr::new("--debug") {
                options.debug = true;
            } else if arg == OsStr::new("--scan") {
                options.scan_only = true;
            }
        }
        options
    }
}

fn main() {
    let options = Options::parse(std::env::args_os().skip(1));
    if let Err(error) = run(&options) {
        if error.downcast_ref::<AppAlreadyRunning>().is_some() {
            if options.debug {
                println!("APP_ALREADY_RUNNING=1");
            } else {
                show_dialog(
                    "Codex App 已在运行，请先正常退出后再启动 Codex Fast。",
                    DialogKind::Info,
                );
            }
            return;
        }

        let message = format!("{error:#}");
        if options.debug {
            eprintln!("ERROR={message}");
        } else {
            show_dialog(&message, DialogKind::Error);
        }
        std::process::exit(1);
    }
}

fn run(options: &Options) -> Result<()> {
    if options.debug {
        enable_debug_console()?;
    }
    if options.scan_only {
        run_scan()
    } else {
        run_launch(options.debug)
    }
}

/// Reports what would be patched without touching the app.
fn run_scan() -> Result<()> {
    let install = discover_codex_install()?;
    print_install(&install);
    println!(
        "APP_ALREADY_RUNNING={}",
        u8::from(is_codex_app_running(&install, None)?)
    );

    let plan = inspect(&install)?;
    verify_plan_snapshots(&plan)?;
    println!("SCAN_OK=1");
    Ok(())
}

/// Patches the renderer and stays attached for the lifetime of the app.
fn run_launch(debug: bool) -> Result<()> {
    let install = discover_codex_install()?;
    let _launcher_guard = acquire_launcher_guard(&install)?;
    print_install(&install);
    if is_codex_app_running(&install, None)? {
        return Err(AppAlreadyRunning.into());
    }

    let plan = inspect(&install)?;
    if plan.patch_set.status == PatchStatus::Degraded && !debug {
        show_dialog(
            &plan.patch_set.format_messages("补丁以降级模式运行："),
            DialogKind::Warning,
        );
    }
    // Re-check the snapshots taken during inspection: nothing may have rewritten
    // app.asar between planning and launch.
    verify_plan_snapshots(&plan)?;

    let runtime_plan = RuntimePlan::from(plan);
    let startup_frame = startup_auto_attach_frame();
    let (app, transport) = launch_codex_with_pipe(&install, &startup_frame)?;
    PatchSession::new(app, transport, runtime_plan).run()
}

fn print_install(install: &CodexInstall) {
    println!("APP_IDENTITY={}", install.identity);
    println!("INSTALL_PATH={}", install.install_path.display());
    println!("EXE={}", install.executable.display());
}

/// Plans the patches and refuses to go further if the result is unsafe.
fn inspect(install: &CodexInstall) -> Result<CompatibilityPlan> {
    let plan = plan_patches(&install.app_asar, &install.identity_files)?;
    print_patch_plan(&plan);
    if plan.patch_set.status == PatchStatus::Unsafe {
        bail!(
            "{}",
            plan.patch_set
                .format_messages("补丁规划不安全，已在启动 Codex 前停止：")
        );
    }
    Ok(plan)
}

fn print_patch_plan(plan: &CompatibilityPlan) {
    let patch_set = &plan.patch_set;
    println!("PATCH_STATUS={:?}", patch_set.status);
    println!(
        "PATCH_SET={} LABEL={} STATUS={:?} ON_UNSAFE=BlockLaunch",
        patch_set.id, patch_set.label, patch_set.status
    );
    for feature in &patch_set.features {
        println!(
            "PATCH_FEATURE={} LABEL={} ROLE={:?} GUARDED_SITE_COUNT={} PATCHED_SITE_COUNT={}",
            feature.id, feature.label, feature.role, feature.guarded_sites, feature.patched_sites
        );
    }
    for message in &patch_set.messages {
        println!("PATCH_MESSAGE={} MESSAGE={message}", patch_set.id);
    }
    println!("RUNTIME_RESOURCE_COUNT={}", plan.resources.len());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_console_and_scan_options() {
        assert_eq!(
            Options::parse(std::iter::empty::<OsString>()),
            Options::default()
        );
        assert_eq!(
            Options::parse(
                ["--scan", "ignored", "--debug"]
                    .into_iter()
                    .map(OsString::from)
            ),
            Options {
                debug: true,
                scan_only: true,
            }
        );
    }
}
