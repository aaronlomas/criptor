//! Inspection of local surfaces for exposed passwords and credentials.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::time::Instant;

use path_clean::PathClean;

use super::{ExposureHit, ExposureSource, ScanReport};

/// Maximum file size examined in temporary directories (512 KiB) to maintain fast scanning.
const MAX_TEMP_FILE_SIZE: u64 = 512 * 1024;

/// Maximum number of temporary files inspected.
const MAX_TEMP_FILES_COUNT: usize = 30;

/// Maximum number of lines inspected from shell history files.
const MAX_HISTORY_LINES: usize = 500;

/// Redacts sensitive secret values to prevent displaying credentials in terminal output.
pub fn redact_secret(val: &str) -> String {
    let trimmed = val.trim();
    let chars: Vec<char> = trimmed.chars().collect();
    if chars.len() <= 6 {
        "***".to_string()
    } else {
        let prefix: String = chars[..2].iter().collect();
        let suffix: String = chars[chars.len() - 2..].iter().collect();
        format!("{}***{}", prefix, suffix)
    }
}

/// Determines whether a string is an obvious placeholder rather than a real secret.
fn is_placeholder(s: &str) -> bool {
    let lower = s.to_lowercase();
    matches!(
        lower.as_str(),
        "" | "none"
            | "null"
            | "true"
            | "false"
            | "xxxx"
            | "test"
            | "example"
            | "placeholder"
            | "dummy"
            | "password"
            | "secret"
            | "changeme"
            | "your_password"
            | "your_token"
    )
}

/// Identifies connection strings containing embedded plaintext credentials according to RFC 3986.
fn extract_uri_credential(s: &str) -> Option<(String, String)> {
    let mut search_idx = 0;
    while let Some(rel_scheme_end) = s[search_idx..].find("://") {
        let scheme_end = search_idx + rel_scheme_end;
        let after_scheme = &s[scheme_end + 3..];

        // Enforces URI authority delimiters (slash, query, fragment, quote or whitespace)
        let authority_end = after_scheme
            .find(|c: char| {
                c == '/' || c == '?' || c == '#' || c.is_whitespace() || c == '"' || c == '\''
            })
            .unwrap_or(after_scheme.len());

        let authority = &after_scheme[..authority_end];

        if let Some(at_idx) = authority.find('@') {
            let userinfo = &authority[..at_idx];
            if let Some(colon_idx) = userinfo.find(':') {
                let pass = &userinfo[colon_idx + 1..];
                if pass.len() >= 4 && !is_placeholder(pass) {
                    return Some((
                        "Database or service URL with embedded password".to_string(),
                        redact_secret(pass),
                    ));
                }
            }
        }

        search_idx = scheme_end + 3;
    }
    None
}

/// Checks for recognized prefixes of popular API tokens and keys.
fn check_api_token(s: &str) -> Option<(&'static str, String)> {
    let trimmed = s.trim();

    if trimmed.starts_with("ghp_")
        || trimmed.starts_with("gho_")
        || trimmed.starts_with("ghu_")
        || trimmed.starts_with("ghs_")
        || trimmed.starts_with("ghr_")
    {
        return Some(("GitHub personal or OAuth token", redact_secret(trimmed)));
    }
    if trimmed.starts_with("glpat-") {
        return Some(("GitLab personal access token", redact_secret(trimmed)));
    }
    if trimmed.starts_with("xoxb-")
        || trimmed.starts_with("xoxp-")
        || trimmed.starts_with("xoxa-")
        || trimmed.starts_with("xoxr-")
    {
        return Some(("Slack API token", redact_secret(trimmed)));
    }
    if (trimmed.starts_with("AKIA") || trimmed.starts_with("ASIA")) && trimmed.len() >= 20 {
        let key_part = &trimmed[..20];
        if key_part
            .chars()
            .all(|c| c.is_ascii_alphanumeric() && !c.is_ascii_lowercase())
        {
            return Some(("AWS Access Key ID", redact_secret(trimmed)));
        }
    }
    if trimmed.starts_with("sk-") && trimmed.len() >= 20 {
        return Some(("API secret key (sk-*)", redact_secret(trimmed)));
    }
    if trimmed.contains("-----BEGIN ") && trimmed.contains("PRIVATE KEY-----") {
        return Some((
            "Unencrypted private key block",
            "***PRIVATE KEY***".to_string(),
        ));
    }

    None
}

/// Identifies inline key-value assignments containing sensitive words.
fn check_assignment(line: &str) -> Option<(&'static str, String)> {
    let lower = line.to_lowercase();
    let keywords = [
        ("password=", "Plaintext password assignment"),
        ("password:", "Plaintext password field"),
        ("passwd=", "Plaintext password assignment"),
        ("passwd:", "Plaintext password field"),
        ("api_key=", "API key assignment"),
        ("api_key:", "API key field"),
        ("apikey=", "API key assignment"),
        ("secret_key=", "Secret key assignment"),
        ("secret_key:", "Secret key field"),
        ("access_token=", "Access token assignment"),
        ("access_token:", "Access token field"),
        ("auth_token=", "Authentication token assignment"),
    ];

    for (kw, label) in keywords {
        if let Some(pos) = lower.find(kw) {
            let val_part = line[pos + kw.len()..].trim();
            let secret = val_part
                .split(|c: char| {
                    c.is_whitespace()
                        || c == ';'
                        || c == '&'
                        || c == ','
                        || c == '"'
                        || c == '\''
                        || c == '}'
                })
                .next()
                .unwrap_or("")
                .trim_matches(|c| c == '"' || c == '\'');

            if secret.len() >= 4 && !is_placeholder(secret) {
                return Some((label, redact_secret(secret)));
            }
        }
    }
    None
}

/// Inspects environment variables for exposed credentials and tokens.
fn scan_environment(hits: &mut Vec<ExposureHit>) {
    let ignored_names = [
        "PATH",
        "LANG",
        "PWD",
        "OLDPWD",
        "SHELL",
        "TERM",
        "DISPLAY",
        "COLORTERM",
        "LS_COLORS",
        "XDG_DATA_DIRS",
        "XDG_CONFIG_DIRS",
        "XDG_CURRENT_DESKTOP",
        "XDG_SESSION_TYPE",
        "DESKTOP_SESSION",
        "KEYBOARD",
        "GPG_KEY_ID",
    ];

    let sensitive_var_substrings = [
        "PASS",
        "SECRET",
        "TOKEN",
        "APIKEY",
        "API_KEY",
        "CREDENTIAL",
        "AUTH_KEY",
        "ACCESS_KEY",
    ];

    for (name, val) in std::env::vars() {
        if ignored_names.contains(&name.as_str()) {
            continue;
        }

        // Check for URI containing embedded password in value
        if let Some((pattern, redacted)) = extract_uri_credential(&val) {
            hits.push(ExposureHit {
                source: ExposureSource::Environment,
                location: name.clone(),
                pattern_name: pattern,
                redacted_value: redacted,
                recommendation:
                    "Extract embedded database credentials and load them from an encrypted vault."
                        .to_string(),
            });
            continue;
        }

        // Check for recognized API token prefixes in value
        if let Some((pattern, redacted)) = check_api_token(&val) {
            hits.push(ExposureHit {
                source: ExposureSource::Environment,
                location: name.clone(),
                pattern_name: pattern.to_string(),
                redacted_value: redacted,
                recommendation:
                    "Revoke exposed API tokens and load secrets on-demand using vault credentials."
                        .to_string(),
            });
            continue;
        }

        // Check for sensitive variable naming
        let upper_name = name.to_uppercase();
        let matches_name = sensitive_var_substrings
            .iter()
            .any(|sub| upper_name.contains(sub));

        if matches_name && val.len() >= 4 && !is_placeholder(&val) {
            hits.push(ExposureHit {
                source: ExposureSource::Environment,
                location: name,
                pattern_name: "Sensitive variable contains plaintext value".to_string(),
                redacted_value: redact_secret(&val),
                recommendation:
                    "Avoid exporting plain credentials in environment variables; pass via secure channels."
                        .to_string(),
            });
        }
    }
}

/// Inspects text files located directly within the system temporary folder.
fn scan_temp_directory(hits: &mut Vec<ExposureHit>) {
    let temp_dir = std::env::temp_dir().clean();
    let Ok(entries) = std::fs::read_dir(&temp_dir) else {
        return;
    };

    let allowed_extensions = [
        "log", "txt", "json", "env", "dump", "conf", "yaml", "yml", "sh",
    ];

    let mut inspected = 0;
    for entry in entries.flatten() {
        if inspected >= MAX_TEMP_FILES_COUNT {
            break;
        }

        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_file() {
            continue;
        }

        let path = entry.path();
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        if !allowed_extensions.contains(&ext.as_str()) {
            continue;
        }

        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        if metadata.len() > MAX_TEMP_FILE_SIZE {
            continue;
        }

        inspected += 1;
        scan_text_file(
            &path,
            ExposureSource::TempFile,
            hits,
            "Remove temporary logs or debug artifacts containing credentials.",
        );
    }
}

/// Inspects user shell history files for passwords supplied in CLI commands.
fn scan_shell_history(hits: &mut Vec<ExposureHit>) {
    let mut history_paths = Vec::new();

    if let Ok(home) = std::env::var("HOME") {
        let home_path = PathBuf::from(home);
        history_paths.push(home_path.join(".bash_history"));
        history_paths.push(home_path.join(".zsh_history"));
        history_paths.push(home_path.join(".history"));
    }

    if let Ok(app_data) = std::env::var("APPDATA") {
        let ps_history = PathBuf::from(app_data)
            .join("Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt");
        history_paths.push(ps_history);
    }

    for path in history_paths {
        let cleaned = path.clean();
        if cleaned.is_file() {
            scan_history_file(&cleaned, hits);
        }
    }
}

/// Parses the lines of a shell history file searching for command-line password flags.
fn scan_history_file(path: &Path, hits: &mut Vec<ExposureHit>) {
    let Ok(file) = File::open(path) else {
        return;
    };
    let reader = BufReader::new(file);
    let lines: Vec<String> = reader.lines().map_while(Result::ok).collect();

    let start = lines.len().saturating_sub(MAX_HISTORY_LINES);
    for (idx, line) in lines[start..].iter().enumerate() {
        let line_num = start + idx + 1;
        let display_path = format!("{}:{}", path.display(), line_num);

        // Check for URI credentials in history
        if let Some((pattern, redacted)) = extract_uri_credential(line) {
            hits.push(ExposureHit {
                source: ExposureSource::ShellHistory,
                location: display_path.clone(),
                pattern_name: pattern,
                redacted_value: redacted,
                recommendation:
                    "Clean history entries containing connection strings with passwords."
                        .to_string(),
            });
            continue;
        }

        // Check for API tokens in history
        if let Some((pattern, redacted)) = check_api_token(line) {
            hits.push(ExposureHit {
                source: ExposureSource::ShellHistory,
                location: display_path.clone(),
                pattern_name: pattern.to_string(),
                redacted_value: redacted,
                recommendation:
                    "Rotate the exposed API token and remove the line from shell history."
                        .to_string(),
            });
            continue;
        }

        // Check for command flags like -pPassword or curl -u user:pass
        if let Some((pattern, redacted)) = check_command_password(line) {
            hits.push(ExposureHit {
                source: ExposureSource::ShellHistory,
                location: display_path,
                pattern_name: pattern.to_string(),
                redacted_value: redacted,
                recommendation:
                    "Avoid passing passwords directly in CLI flags; use config files or prompts."
                        .to_string(),
            });
        }
    }
}

/// Inspects command lines for password arguments such as -p or -u.
fn check_command_password(line: &str) -> Option<(&'static str, String)> {
    let words: Vec<&str> = line.split_whitespace().collect();

    for (i, &word) in words.iter().enumerate() {
        // mysql/mysqldump -pSecret
        if (word.starts_with("-p") || word.starts_with("--password=")) && word.len() > 2 {
            let pass = word
                .trim_start_matches("-p")
                .trim_start_matches("--password=")
                .trim_matches(|c| c == '"' || c == '\'');
            if pass.len() >= 4 && !is_placeholder(pass) {
                return Some(("Command-line password flag (-p)", redact_secret(pass)));
            }
        }

        // curl -u user:pass
        if (word == "-u" || word == "--user") && i + 1 < words.len() {
            let next = words[i + 1].trim_matches(|c| c == '"' || c == '\'');
            if let Some(colon) = next.find(':') {
                let pass = &next[colon + 1..];
                if pass.len() >= 4 && !is_placeholder(pass) {
                    return Some((
                        "curl authentication argument (-u user:pass)",
                        redact_secret(pass),
                    ));
                }
            }
        }

        // sshpass -p pass
        if word == "-p" && i + 1 < words.len() && i > 0 && words[i - 1].contains("sshpass") {
            let pass = words[i + 1].trim_matches(|c| c == '"' || c == '\'');
            if pass.len() >= 4 && !is_placeholder(pass) {
                return Some(("sshpass command line password", redact_secret(pass)));
            }
        }
    }

    // Export statement with password
    if line.trim_start().starts_with("export ") {
        if let Some((label, redacted)) = check_assignment(line) {
            return Some((label, redacted));
        }
    }

    None
}

/// Scans the contents of an arbitrary text file looking for password assignments and tokens.
fn scan_text_file(
    path: &Path,
    source: ExposureSource,
    hits: &mut Vec<ExposureHit>,
    recommendation: &str,
) {
    let Ok(file) = File::open(path) else {
        return;
    };
    let reader = BufReader::new(file);

    for (idx, line_res) in reader.lines().enumerate().take(300) {
        let Ok(line) = line_res else {
            break;
        };
        let line_num = idx + 1;
        let location = format!("{}:{}", path.display(), line_num);

        if let Some((pattern, redacted)) = extract_uri_credential(&line) {
            hits.push(ExposureHit {
                source: source.clone(),
                location: location.clone(),
                pattern_name: pattern,
                redacted_value: redacted,
                recommendation: recommendation.to_string(),
            });
            continue;
        }

        if let Some((pattern, redacted)) = check_api_token(&line) {
            hits.push(ExposureHit {
                source: source.clone(),
                location: location.clone(),
                pattern_name: pattern.to_string(),
                redacted_value: redacted,
                recommendation: recommendation.to_string(),
            });
            continue;
        }

        if let Some((pattern, redacted)) = check_assignment(&line) {
            hits.push(ExposureHit {
                source: source.clone(),
                location,
                pattern_name: pattern.to_string(),
                redacted_value: redacted,
                recommendation: recommendation.to_string(),
            });
        }
    }
}

/// Executes a fast, non-privileged scan across local surfaces for exposed credentials.
pub fn scan_exposed_passwords() -> ScanReport {
    let start = Instant::now();
    let mut hits = Vec::new();

    scan_environment(&mut hits);
    scan_temp_directory(&mut hits);
    scan_shell_history(&mut hits);

    ScanReport {
        hits,
        sources_checked: 3,
        duration: start.elapsed(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_secrets_safely() {
        assert_eq!(redact_secret("1234"), "***");
        assert_eq!(redact_secret("secret1234"), "se***34");
        assert_eq!(redact_secret("ghp_ABC123XYZ456"), "gh***56");
    }

    #[test]
    fn detects_embedded_uri_passwords() {
        let uri = "postgres://admin:superSecretPass123@localhost:5432/mydb";
        let res = extract_uri_credential(uri);
        assert!(res.is_some());
        let (pattern, redacted) = res.unwrap();
        assert!(pattern.contains("password"));
        assert_eq!(redacted, "su***23");
    }

    #[test]
    fn ignores_placeholder_passwords() {
        let uri = "postgres://admin:dummy@localhost:5432/mydb";
        assert!(extract_uri_credential(uri).is_none());
    }

    #[test]
    fn rejects_false_positive_across_json_delimiters() {
        let json_line = r#"{"url":"https://example.com/api/v1","enabled":false,"desc":"mention user @someone"}"#;
        assert!(extract_uri_credential(json_line).is_none());
    }

    #[test]
    fn detects_api_tokens() {
        assert!(check_api_token("ghp_1234567890abcdef1234567890").is_some());
        assert!(check_api_token("glpat-abcdef1234567890").is_some());
        assert!(check_api_token("xoxb-1234-5678-abcdef").is_some());
        assert!(check_api_token("sk-proj-abcdef12345678901234567890").is_some());
    }

    #[test]
    fn detects_command_line_passwords() {
        let cmd = "mysql -u root -pSecret123 -h localhost";
        let res = check_command_password(cmd);
        assert!(res.is_some());
        let (label, redacted) = res.unwrap();
        assert!(label.contains("-p"));
        assert_eq!(redacted, "Se***23");

        let curl_cmd = "curl -u myuser:mypassword123 https://api.example.com";
        let res_curl = check_command_password(curl_cmd);
        assert!(res_curl.is_some());
    }

    #[test]
    fn scan_completes_in_subsecond_time() {
        let report = scan_exposed_passwords();
        assert!(report.sources_checked > 0);
        assert!(report.duration.as_millis() < 1000);
    }
}
