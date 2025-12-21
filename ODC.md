# Coding Rules

AI assistant coding guidelines for this project.

## General

1. **Keep list creation simple** - Don't obsess over list creation. Keep it simple

## Workflow

2. **Read files anytime** - Analyze, explore, understand the codebase freely
3. **Write/Create/Delete only with approval** - Wait for explicit confirmation before editing, creating, or removing files/directories, unless acting on a direct order to do so
   - Direct: "Add a Validate() method to User struct" or "Create a new config.go file"
   - Needs approval: "I think we should add validation" or "We could create a separate config file"

## Code Style

4. **Only 1 consecutive empty newline between functions** - Only 1 consecutive empty newline allowed between functions at top level. Use newlines sparingly, only to separate logical blocks. During edits, actively remove extra blank lines
5. **Use spaces, not tabs** - Use spaces for indentation, not tabs unless really necessary
6. **Short, clean names** - Use short words fully spelled out. Avoid abbreviation and verbose names
   - Good: `user`, `config`, `decrypt` (short words, fully spelled)
   - Avoid: `usr`, `cfg`, `dcrypt` (abbreviations)
   - Avoid: `userConfiguration`, `decryptedFileHandler` (too long)
   - Exception: For small loops, really short names are preferred (e.g., `i`, `j`, `v`, `k`)
   - Prefer generic names over overly specific ones when appropriate (e.g., `key` over `pubKey` over `pubPKCS7Key`)
7. **Short comments inside functions** - One-liners only, no multi-line comment blocks
8. **Rarely comment outside functions** - Let the code speak for itself at the top level. Godoc comments on exported types/functions are fine, but avoid unnecessary comment blocks between functions

## File Organization

9. **Prefer few files** - Create as few files as possible, consolidate related code
   - Keep: user.go with User struct, methods, and validation
   - Avoid: user.go, user_validation.go, user_helpers.go for simple cases
10. **Prefer shallow directory structure** - Avoid deep nesting, keep directories minimal
   - Good: `cmd/`, `pkg/`, `internal/`
   - Avoid: `src/internal/app/services/user/handlers/http/v1/`

## Documentation

11. **Minimal documentation** - README.md should be enough. No creation of additional .md files are allowed unless confirmed
12. **Information hierarchy** - Relevant info first, short descriptions, less relevant details at the end
   - Good: "Encrypts YAML files. Requires Go 1.21+. Uses AES-256. Installation: ..."
   - Bad: "Installation: ... Requirements: ... About: This tool encrypts..."
13. **No emojis in titles** - OK in body text, but keep titles clean
