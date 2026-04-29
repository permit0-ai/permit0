//! Shell command string → token list.
//!
//! Wraps the `shlex` crate with a permit0-friendly error type and a few
//! convenience accessors for the common pattern of "program + rest of tokens".

use thiserror::Error;

/// Errors from tokenizing a shell command.
#[derive(Debug, Clone, Error)]
pub enum TokenizeError {
    /// `shlex` couldn't parse the input (unbalanced quotes, bad escapes, etc.).
    #[error("unable to tokenize command: bad quoting or escape")]
    BadShellSyntax,

    /// The command string was empty or all whitespace.
    #[error("command is empty")]
    Empty,
}

/// The tokenized form of a shell command: the program name plus the rest of
/// the tokens (sub-commands, flags, positional arguments, everything).
///
/// The tokenizer is deliberately "dumb" — it does **not** distinguish flags
/// from positional args here, because that split is parser-specific (e.g.
/// `aws s3 cp src dst` wants two positionals, `gog gmail send --to X` wants
/// zero). Each [`crate::parser::CommandParser`] is responsible for pulling
/// its own structure out of the flat token list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tokens {
    /// The first token, lower-cased (canonical program names are ASCII).
    pub program: String,
    /// Every token after the program name, preserved verbatim.
    pub rest: Vec<String>,
}

impl Tokens {
    /// Tokenize a shell command string.
    ///
    /// ```
    /// use permit0_shell_dispatch::tokenize::Tokens;
    /// let t = Tokens::parse("gog gmail send --to 'alice@acme.com'").unwrap();
    /// assert_eq!(t.program, "gog");
    /// assert_eq!(t.rest, vec!["gmail", "send", "--to", "alice@acme.com"]);
    /// ```
    pub fn parse(cmd: &str) -> Result<Self, TokenizeError> {
        let trimmed = cmd.trim();
        if trimmed.is_empty() {
            return Err(TokenizeError::Empty);
        }

        // Strip environment-variable prefixes — a bash prelude like
        // `AWS_REGION=us-west-2 aws s3 cp ...` would otherwise be parsed with
        // `AWS_REGION=us-west-2` as the program name.
        let cleaned = strip_env_prefix(trimmed);

        let raw = shlex::split(cleaned).ok_or(TokenizeError::BadShellSyntax)?;
        if raw.is_empty() {
            return Err(TokenizeError::Empty);
        }

        let mut iter = raw.into_iter();
        let program = iter
            .next()
            .expect("at least one token")
            .to_ascii_lowercase();
        let rest: Vec<String> = iter.collect();

        Ok(Self { program, rest })
    }
}

/// Strip leading `KEY=value` pairs (one or more) before the real program name.
///
/// `AWS_REGION=us-west-2 aws s3 ls` → `aws s3 ls`
///
/// We treat a token as an env prefix iff it (a) contains `=` and (b) the part
/// before `=` is all uppercase letters / digits / underscores — matching
/// POSIX environment-variable naming. Anything else (paths, arguments that
/// happen to contain `=`, etc.) is left alone.
fn strip_env_prefix(cmd: &str) -> &str {
    let mut remaining = cmd;
    loop {
        let Some((head, tail)) = remaining.split_once(char::is_whitespace) else {
            return remaining;
        };

        if !is_env_assignment(head) {
            return remaining;
        }
        remaining = tail.trim_start();
    }
}

fn is_env_assignment(token: &str) -> bool {
    let Some((name, _)) = token.split_once('=') else {
        return false;
    };
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple() {
        let t = Tokens::parse("gog gmail send").unwrap();
        assert_eq!(t.program, "gog");
        assert_eq!(t.rest, vec!["gmail", "send"]);
    }

    #[test]
    fn flags_and_quoted_values() {
        let t = Tokens::parse(r#"gog gmail send --to "alice@acme.com" --subject 'Hi there'"#)
            .unwrap();
        assert_eq!(t.program, "gog");
        assert_eq!(
            t.rest,
            vec!["gmail", "send", "--to", "alice@acme.com", "--subject", "Hi there"]
        );
    }

    #[test]
    fn program_lowercased() {
        let t = Tokens::parse("GH pr create").unwrap();
        assert_eq!(t.program, "gh");
    }

    #[test]
    fn env_prefix_stripped() {
        let t = Tokens::parse("AWS_REGION=us-west-2 aws s3 ls s3://bucket").unwrap();
        assert_eq!(t.program, "aws");
        assert_eq!(t.rest, vec!["s3", "ls", "s3://bucket"]);
    }

    #[test]
    fn multiple_env_prefixes_stripped() {
        let t = Tokens::parse("FOO=1 BAR=baz stripe charges create").unwrap();
        assert_eq!(t.program, "stripe");
    }

    #[test]
    fn non_env_looking_leading_token_is_not_stripped() {
        // A lowercase-left-of-= is not an env var; must be the program.
        let t = Tokens::parse("weird=tool do_thing").unwrap();
        assert_eq!(t.program, "weird=tool");
    }

    #[test]
    fn empty_is_error() {
        assert!(matches!(Tokens::parse(""), Err(TokenizeError::Empty)));
        assert!(matches!(Tokens::parse("   "), Err(TokenizeError::Empty)));
    }

    #[test]
    fn unbalanced_quote_is_error() {
        assert!(matches!(
            Tokens::parse(r#"gog gmail send --to "alice"#),
            Err(TokenizeError::BadShellSyntax)
        ));
    }
}
