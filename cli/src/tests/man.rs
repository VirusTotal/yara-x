use std::collections::BTreeSet;
use std::path::Path;
use std::{env, fs};

use clap::Command;
use clap_mangen::Man;
use clap_mangen::roff::{Inline, Roff, bold, italic, roman};

/// Verifies that the committed man pages under `cli/man/*.1` match the current
/// `clap` CLI definition.
///
/// To regenerate the man pages after changing commands, options, or help text,
/// run:
///
/// ```text
/// UPDATE_MANPAGES=1 CARGO_BIN_EXE_yr=target/debug/yr \
///     cargo test -p yara-x-cli --bin yr man_pages_are_up_to_date
/// ```
#[test]
fn man_pages_are_up_to_date() {
    let man_dir = Path::new("man");
    let update = env::var("UPDATE_MANPAGES").is_ok();

    if update {
        fs::create_dir_all(man_dir).unwrap();
    }

    let mut root = crate::commands::cli()
        .name("yr")
        .bin_name("yr")
        .disable_help_subcommand(true);

    // Exclude the developer-only `debug` subcommand even when tests are built
    // with `--features debug-cmd`.
    #[cfg(feature = "debug-cmd")]
    {
        root = root.mut_subcommand("debug", |sub| sub.hide(true));
    }

    // Build once so clap materializes auto-generated flags (`-h`/`--help`,
    // `-V`/`--version`) and propagates `display_name`/`bin_name` to nested
    // subcommands (e.g. `yr-scan`, `yr-fix-encoding`).
    root.build();

    let mut generated = BTreeSet::new();
    let mut outdated = Vec::new();

    generate_recursive(
        &root,
        &[],
        man_dir,
        update,
        &mut generated,
        &mut outdated,
    );

    assert!(
        outdated.is_empty(),
        "outdated or missing man page(s) in cli/man/: {outdated:?}.\n\
         Regenerate them with:\n\
         UPDATE_MANPAGES=1 CARGO_BIN_EXE_yr=target/debug/yr \
         cargo test -p yara-x-cli --bin yr man_pages_are_up_to_date"
    );

    // Ensure no stale `.1` files remain in `cli/man/` after a subcommand is
    // removed or renamed.
    let existing: BTreeSet<String> = fs::read_dir(man_dir)
        .unwrap()
        .filter_map(|entry| {
            let name = entry.ok()?.file_name().into_string().ok()?;
            name.ends_with(".1").then_some(name)
        })
        .collect();

    let stale: Vec<_> = existing.difference(&generated).collect();
    if update {
        for filename in stale {
            fs::remove_file(man_dir.join(filename)).unwrap();
        }
    } else {
        assert!(
            stale.is_empty(),
            "stale man page(s) in cli/man/: {stale:?}. Remove them or re-run \
             with UPDATE_MANPAGES=1."
        );
    }
}

fn generate_recursive(
    cmd: &Command,
    parents: &[String],
    man_dir: &Path,
    update: bool,
    generated: &mut BTreeSet<String>,
    outdated: &mut Vec<String>,
) {
    let display_name =
        cmd.get_display_name().unwrap_or_else(|| cmd.get_name()).to_owned();

    let mut next_parents = parents.to_vec();
    next_parents.push(display_name.clone());

    for sub in cmd.get_subcommands().filter(|s| !s.is_hide_set()) {
        generate_recursive(
            sub,
            &next_parents,
            man_dir,
            update,
            generated,
            outdated,
        );
    }

    // Clear `version` after `root.build()` has already materialized the
    // `-V`/`--version` option, so committed man pages stay version-neutral and
    // do not churn on every release bump.
    let mut cmd_for_man = cmd.clone();
    cmd_for_man = cmd_for_man.version(None::<&str>).long_version(None::<&str>);

    let man = Man::new(cmd_for_man)
        .title(display_name.to_uppercase())
        .section("1")
        // `roff` does not quote empty strings; passing `""` explicitly keeps
        // `"YARA-X"` in the 4th `.TH` (source) slot instead of the date slot.
        .date("\"\"")
        .source("YARA-X")
        .manual("User Commands");

    let filename = man.get_filename();
    let mut buf = Vec::new();
    man.render(&mut buf).unwrap();

    // Append a `SEE ALSO` section without duplicating `roff`'s preamble.
    let mut see_also = Roff::new();
    see_also.control("SH", ["SEE ALSO"]);
    if parents.is_empty() {
        see_also.text([
            roman("Full CLI documentation: "),
            italic("https://virustotal.github.io/yara-x/docs/cli/"),
        ]);
    } else {
        let mut refs: Vec<Inline> = Vec::new();
        for (i, parent) in parents.iter().rev().enumerate() {
            if i > 0 {
                refs.push(roman(", "));
            }
            refs.push(bold(parent));
            refs.push(roman("(1)"));
        }
        see_also.text(refs);
    }
    buf.extend_from_slice(see_also.to_roff().as_bytes());

    let content = format_roff(&String::from_utf8(buf).unwrap());
    let path = man_dir.join(&filename);

    if update {
        fs::write(&path, &content).unwrap();
    } else {
        let existing = fs::read_to_string(&path).ok();
        if existing.as_deref() != Some(content.as_str()) {
            outdated.push(filename.clone());
        }
    }

    generated.insert(filename);
}

/// Cleans up `clap_mangen`'s roff output so multi-line example blocks and
/// option tables keep their line breaks instead of being reflowed onto a
/// single line by `man`.
fn format_roff(input: &str) -> String {
    let lines: Vec<&str> = input.lines().map(str::trim_end).collect();
    let mut out = String::with_capacity(input.len() + 64);
    let mut i = 0;
    let mut expect_example_block = false;

    while i < lines.len() {
        let line = lines[i];

        if line == "Examples:" {
            expect_example_block = true;
            out.push_str(line);
            out.push('\n');
            i += 1;
            continue;
        }

        if expect_example_block {
            if line.is_empty() || line == ".PP" {
                out.push_str(line);
                out.push('\n');
                i += 1;
                continue;
            }
            expect_example_block = false;
            if !line.starts_with('.') {
                out.push_str(".nf\n");
                while i < lines.len()
                    && !lines[i].is_empty()
                    && !lines[i].starts_with('.')
                {
                    out.push_str(lines[i]);
                    out.push('\n');
                    i += 1;
                }
                out.push_str(".fi\n");
                continue;
            }
        }

        // Preserve line breaks in consecutive `--option ...` listing lines
        // (e.g. `--recursive` depth examples).
        if line.starts_with(r"\-\-")
            && lines.get(i + 1).is_some_and(|next| next.starts_with(r"\-\-"))
        {
            out.push_str(".nf\n");
            while i < lines.len() && lines[i].starts_with(r"\-\-") {
                out.push_str(lines[i]);
                out.push('\n');
                i += 1;
            }
            out.push_str(".fi\n");
            continue;
        }

        out.push_str(line);
        out.push('\n');
        i += 1;
    }

    out
}
