# permit0 Claude Code Skills

Skills shipped with this repo. A "skill" is a markdown file
(`SKILL.md`) that Claude Code loads as specialized guidance when its
trigger conditions match.

## Available skills

| Skill | Description |
|-------|-------------|
| [`permit0-claude-code-setup`](permit0-claude-code-setup/SKILL.md) | Walk a user through integrating permit0 with Claude Code from scratch — install Rust, build, OAuth, configure `~/.claude.json`, verify, switch to enforce mode |

## Install

Symlink (or copy) the skills you want into your user skills directory:

```bash
# From this repo's root:
mkdir -p ~/.claude/skills
ln -s "$(pwd)/skills/permit0-claude-code-setup" ~/.claude/skills/permit0-claude-code-setup
```

After symlinking, fully restart Claude Code. The skill activates
automatically when you ask Claude to do something matching its
description (e.g. "set up permit0 with Claude Code").

To check it's loaded:

```
> What skills do you have related to permit0?
```

## Uninstall

```bash
rm ~/.claude/skills/permit0-claude-code-setup
```

(Just removes the symlink; the source in this repo is untouched.)

## Adding a new skill

1. Create `skills/<name>/SKILL.md` with frontmatter:
   ```yaml
   ---
   name: <name>
   description: "When the skill should activate, in 1-2 sentences."
   ---
   ```
2. Body: instructional content for Claude (not for the end user).
   Write in the imperative ("Run X, then check Y, before doing Z").
3. Reference repo paths relative to repo root (e.g.
   `<repo>/packs/email/risk_rules/send.yaml`).
4. Add a row to the **Available skills** table above.
