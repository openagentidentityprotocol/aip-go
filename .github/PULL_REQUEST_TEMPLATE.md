## Summary

<!-- Describe what this PR does in 1-3 sentences -->

## Related Issues

<!-- Link to related issues: Fixes #123, Closes #456 -->

## Type of Change

<!-- Check all that apply -->

- [ ] 🐛 Bug fix (non-breaking change that fixes an issue)
- [ ] ✨ New feature (non-breaking change that adds functionality)
- [ ] 💥 Breaking change (fix or feature that would cause existing functionality to change)
- [ ] 📝 Documentation update
- [ ] 🔧 Configuration change
- [ ] ♻️ Refactoring (no functional changes)
- [ ] 🧪 Test improvement
- [ ] 🔒 Security fix

## Changes Made

<!-- List the specific changes made -->

-
-
-

## Testing

<!-- Describe how you tested these changes -->

- [ ] Unit tests added/updated
- [ ] Manual testing performed
- [ ] Tested with real MCP server
- [ ] Tested policy enforcement

### Test Commands

```bash
# Commands used to test
cd proxy
make test
make build
./bin/aip --policy examples/agent.yaml --target "python3 test/echo_server.py" --verbose
```

## Policy Impact

<!-- If this PR affects policy behavior, describe the impact -->

- [ ] No policy changes
- [ ] New policy feature (describe below)
- [ ] Policy behavior change (describe migration path)

## Security Checklist

<!-- For security-sensitive changes -->

- [ ] No new dependencies with known vulnerabilities
- [ ] No secrets or credentials in code
- [ ] Audit logging maintained for new operations
- [ ] Input validation added for new parameters
- [ ] Documentation updated for security implications

## Documentation

- [ ] README updated (if needed)
- [ ] Code comments added for complex logic
- [ ] Example configurations updated
- [ ] CHANGELOG entry added (for user-facing changes)

## Screenshots / Recordings

<!-- If applicable, add screenshots or recordings demonstrating the change -->

## Checklist

- [ ] My code follows the project's code style (`make lint` passes)
- [ ] I have performed a self-review of my code
- [ ] I have commented my code, particularly in hard-to-understand areas
- [ ] My changes generate no new warnings
- [ ] New and existing unit tests pass locally (`make test`)
- [ ] Any dependent changes have been merged and published

---

<!-- For maintainers -->
/cc @ArangoGutierrez
