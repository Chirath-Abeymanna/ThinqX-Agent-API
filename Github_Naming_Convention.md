# GitHub Naming Conventions

## 🌿 Branch Naming Convention

Use the following format for all branches:

```
<Feature>/<author>/<subFeature>
```

### Branch Types

- `Workflow/` 
- `Agents/` 

### Examples

```bash
feature/john/user-authentication

feature/sarah/payment-integration

bugfix/mike/login-validation-error

hotfix/alice/critical-security-patch

chore/bob/update-dependencies

docs/emma/api-documentation

refactor/tom/database-connection-pool
```

## 💬 Commit Message Convention

Follow the **Conventional Commits** format:

```
<type>: <Message>
```

### Commit Types

- `Feature:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation changes
- `style:` - Code formatting (no logic changes)
- `refactor:` - Code refactoring
- `ci:` - CI/CD changes
- `Docker` - Docker changes

### Commit Message Rules

- **First line**: Max 50 characters
- **Description**: Start with lowercase, no period at end
- **Body** (optional): Wrap at 72 characters, explain "what" and "why"

### Examples

```bash
feat: add user authentication system
fix: resolve login validation error
docs: update API documentation
style: format code with gofmt
refactor: optimize database connection pool
ci: add Docker build to GitHub Actions
```

## 🔄 Workflow Process

### 1. Create Branch

```bash
git checkout -b feature/yourname/short-description
```

### 2. Make Changes & Commit

```bash
git add .
git commit -m "feat: implement user registration endpoint"
```

### 3. Push Branch

```bash
git push origin  <Branch_name>
```

### 4. Create Pull Request

- **Always create a PR** after pushing your branch
- Use descriptive PR title matching your main commit
- Add reviewers and assign yourself
- Link related issues with `Fixes #123` or `Closes #456`

## 🚫 What NOT to Do

**Bad Branch Names:**

```bash
fix-bug                    # Missing author
john/new-feature          # Missing type
feature/john              # Missing description
```

**Bad Commit Messages:**

```bash
"updated stuff"           # Too vague
"Fixed bug"              # No type prefix
"FEAT: NEW LOGIN"        # All caps
"feat: Added new login system that supports OAuth and JWT authentication with Redis caching"  # Too long
```

**Remember:**

- Always work on feature branches, never directly on `main`
- Keep commits atomic (one logical change per commit)
- Write commit messages as if completing: "This commit will..."
