//! Explicit developer tracer using isolated Services, a configured provider and
//! the real pinned Atomic host. This does not activate ordinary Atomic workspaces.

#[cfg(not(unix))]
fn main() -> std::process::ExitCode {
    eprintln!("The Atomic T1 tracer requires a supported Unix execution profile.");
    std::process::ExitCode::FAILURE
}

#[cfg(unix)]
fn main() -> std::process::ExitCode {
    supported::run()
}

#[cfg(unix)]
mod supported {
    use std::{path::PathBuf, process::ExitCode, time::Duration};

    use intent_services::{
        atomic_tracer::{run_and_write_report, TracerOptions, TracerOutcome},
        atomic_tracer_runtime::{ServicesTracerConfig, ServicesTracerDriver},
    };

    const HELP: &str = "Usage: atomic-tracer --directory <new-run-directory> --host <pinned-host-binary> --provider <configured-provider> [--model <model>] [--timeout-seconds <seconds>] [--node <node-binary>]\n\nRuns one Git-authoritative task against an isolated daemon database and fixture.\nUses a real configured provider and real Atomic host; setup failures do not count as a pass.\nThe fixed test and report are retained under --directory. Existing scenarios are refused.\nDefaults: --timeout-seconds 300, --node node.\n";

    struct Arguments {
        directory: PathBuf,
        host: PathBuf,
        provider: String,
        model: Option<String>,
        timeout: Duration,
        node: PathBuf,
    }

    fn parse() -> Result<Option<Arguments>, String> {
        let mut args = std::env::args_os().skip(1);
        let mut directory = None;
        let mut host = None;
        let mut provider = None;
        let mut model = None;
        let mut timeout = Duration::from_secs(300);
        let mut node = PathBuf::from("node");
        while let Some(flag) = args.next() {
            if flag == "--help" || flag == "-h" {
                return Ok(None);
            }
            let flag = flag.to_str().ok_or("option names must be UTF-8")?;
            if !matches!(
                flag,
                "--directory"
                    | "--host"
                    | "--provider"
                    | "--model"
                    | "--timeout-seconds"
                    | "--node"
            ) {
                return Err(format!("unknown argument {flag}"));
            }
            let value = args.next().ok_or_else(|| format!("{flag} needs a value"))?;
            match flag {
                "--directory" => directory = Some(PathBuf::from(value)),
                "--host" => host = Some(PathBuf::from(value)),
                "--provider" => {
                    provider = Some(value.into_string().map_err(|_| "provider must be UTF-8")?);
                }
                "--model" => model = Some(value.into_string().map_err(|_| "model must be UTF-8")?),
                "--node" => node = PathBuf::from(value),
                "--timeout-seconds" => {
                    let seconds = value
                        .to_str()
                        .and_then(|s| s.parse::<u64>().ok())
                        .filter(|seconds| (1..=3_600).contains(seconds))
                        .ok_or("timeout-seconds must be an integer from 1 to 3600")?;
                    timeout = Duration::from_secs(seconds);
                }
                _ => unreachable!(),
            }
        }
        let directory = directory.ok_or("--directory is required")?;
        let directory = if directory.is_absolute() {
            directory
        } else {
            std::env::current_dir()
                .map_err(|error| format!("current directory: {error}"))?
                .join(directory)
        };
        let host = host.ok_or("--host is required; provide the actual pinned native host")?;
        let host = if host.is_absolute() {
            host
        } else {
            std::env::current_dir()
                .map_err(|error| format!("current directory: {error}"))?
                .join(host)
        };
        let provider = provider
            .filter(|p: &String| !p.trim().is_empty())
            .ok_or("--provider is required")?;
        Ok(Some(Arguments {
            directory,
            host,
            provider,
            model,
            timeout,
            node,
        }))
    }

    pub(super) fn run() -> ExitCode {
        // The Linux process owner must dispatch before Tokio starts any threads.
        #[cfg(target_os = "linux")]
        if let Some(exit) = intent_services::dispatch_diagnostic_owner() {
            return exit;
        }
        // AgentManager names its current executable as the authenticated stdio
        // bridge. Reuse the production bridge rather than spawning another daemon.
        let bridge_args: Vec<_> = std::env::args_os().skip(1).collect();
        if bridge_args
            .first()
            .is_some_and(|argument| argument == "mcp-bridge")
        {
            let address = match bridge_args.as_slice() {
                [_, option, address] if option == "--connect" => address.to_str(),
                _ => None,
            };
            let Some(address) = address else {
                eprintln!("mcp-bridge requires --connect <address>");
                return ExitCode::from(2);
            };
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    eprintln!("Cannot start MCP bridge runtime: {error}");
                    return ExitCode::FAILURE;
                }
            };
            // Tokio stdin may leave a pending blocking read after disconnect. Match
            // intentd's production exit semantics instead of waiting for runtime drop.
            match runtime.block_on(intent_acp::run_stdio_bridge(address)) {
                Ok(()) => std::process::exit(0),
                Err(error) => {
                    eprintln!("MCP bridge failed: {error}");
                    std::process::exit(1);
                }
            }
        }
        let args = match parse() {
            Ok(Some(args)) => args,
            Ok(None) => {
                print!("{HELP}");
                return ExitCode::SUCCESS;
            }
            Err(error) => {
                eprintln!("{error}\n\n{HELP}");
                return ExitCode::from(2);
            }
        };
        let runtime = match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(error) => {
                eprintln!("Cannot start tracer runtime: {error}");
                return ExitCode::FAILURE;
            }
        };
        runtime.block_on(async move {
            let mut driver = match ServicesTracerDriver::new(ServicesTracerConfig {
                directory: args.directory.clone(),
                host_binary: args.host,
                provider: args.provider,
                model: args.model,
                timeout: args.timeout,
            }) {
                Ok(driver) => driver.with_composer(intent_app::compose),
                Err(error) => {
                    eprintln!("Tracer setup failed: {error}");
                    return ExitCode::FAILURE;
                }
            };
            let mut options = TracerOptions::new(args.directory.clone());
            options.node_binary = args.node;
            match run_and_write_report(&mut driver, &options).await {
                Ok(report) => {
                    println!("Report: {}", args.directory.join("report.md").display());
                    if report.outcome == TracerOutcome::Passed {
                        ExitCode::SUCCESS
                    } else {
                        eprintln!(
                            "Tracer failed: {}",
                            report.error.as_deref().unwrap_or("see retained report")
                        );
                        ExitCode::FAILURE
                    }
                }
                Err(error) => {
                    eprintln!("Tracer refused or could not retain its report: {error}");
                    ExitCode::FAILURE
                }
            }
        })
    }
}
