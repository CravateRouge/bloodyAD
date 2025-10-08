# bloodyAD Async Refactoring Guide

## Summary
This document explains the async refactoring pattern used to convert bloodyAD from using threading hacks to native async/await.

## What Was Done

### Core Changes
1. **main.py**: Converted `main()` to `async def main()` and wrapped with `asyncio.run()`
2. **ldap.py**: 
   - Removed threading (no more `loop`, `thread`, `closeThread`)
   - Created async factory method `Ldap.create(conn)` instead of `__init__(conn)`
   - Converted all methods to async: `bloodyadd`, `bloodydelete`, `bloodymodify`, `dnResolver`, `bloodysearch`, `close`, `getTrustMap`
   - Changed `policy` from cached_property to `async def get_policy()`
3. **config.py**: Made `ConnectionHandler.ldap` property async
4. **utils.py**: Converted helper functions to async: `renderSD`, `getSD`, `findCompatibleDC`, `connectReachable`, `LazyAdSchema._resolveAll`
5. **get.py**: Converted all CLI functions to async (7 functions)
6. **set.py**: Converted all CLI functions to async (4 functions)

## Conversion Pattern

### Step 1: Function Signature
```python
# Before
def my_function(conn, param1, param2):

# After
async def my_function(conn, param1, param2):
```

### Step 2: Get ldap Connection
Add at the beginning of function:
```python
ldap = await conn.ldap
```

### Step 3: Replace Direct Method Calls
```python
# Before
conn.ldap.bloodymodify(target, changes)
conn.ldap.bloodyadd(target, **kwargs)
conn.ldap.bloodydelete(target)

# After  
await ldap.bloodymodify(target, changes)
await ldap.bloodyadd(target, **kwargs)
await ldap.bloodydelete(target)
```

### Step 4: Replace Generator/Iterator Usage
```python
# Before
entry = next(conn.ldap.bloodysearch(target, attr=["objectSid"]))

# After
entry = None
async for e in ldap.bloodysearch(target, attr=["objectSid"]):
    entry = e
    break
```

### Step 5: Handle Generators in Loops
```python
# Before
for entry in conn.ldap.bloodysearch(...):
    process(entry)

# After
async for entry in ldap.bloodysearch(...):
    process(entry)
```

### Step 6: Yield from Async Generators
```python
# Before
entries = conn.ldap.bloodysearch(...)
yield from entries

# After
entries = ldap.bloodysearch(...)
async for entry in entries:
    yield entry
```

### Step 7: Update Property Access
```python
# Before
conn.ldap.domainNC
conn.ldap.configNC

# After (cached during create, so direct access is fine)
ldap.domainNC
ldap.configNC
```

## Remaining Work

### add.py (11 functions to convert)
All follow the same pattern above:

1. `badSuccessor(conn, dmsa, t, ou)` - Complex, has nested `getWeakOU` function
2. `computer(conn, hostname, newpass, ou, lifetime)`
3. `dcsync(conn, trustee)`
4. `dnsRecord(conn, name, data, dnstype, zone, ttl, ...)`
5. `genericAll(conn, target, trustee)`
6. `groupMember(conn, group, member)`
7. `rbcd(conn, target, service)`
8. `shadowCredentials(conn, target, path)`
9. `uac(conn, target, f)`
10. `user(conn, sAMAccountName, newpass, ou, lifetime)`

### remove.py (8 functions to convert)
All follow the same pattern above:

1. `dcsync(conn, trustee)`
2. `dnsRecord(conn, name, data, dnstype, zone, ...)`
3. `genericAll(conn, target, trustee)`
4. `groupMember(conn, group, member)`
5. `object(conn, target)`
6. `rbcd(conn, target, service)`
7. `shadowCredentials(conn, target, key)`
8. `uac(conn, target, f)`

## Special Cases

### Nested Functions
When a function has nested helper functions that use `conn.ldap`, those also need to be async:

```python
# Before
def outer(conn, param):
    def inner(conn):
        entry = next(conn.ldap.bloodysearch(...))
        return entry
    result = inner(conn)

# After
async def outer(conn, param):
    async def inner(conn):
        ldap = await conn.ldap
        entry = None
        async for e in ldap.bloodysearch(...):
            entry = e
            break
        return entry
    result = await inner(conn)
```

### Functions Calling Other CLI Functions
When one function calls another (e.g., `genericAll` calls `getSD`):

```python
# If getSD is now async
new_sd, _ = await utils.getSD(conn, target)
```

### Complex Patterns with Multiple Calls
```python
# Before
entries = conn.ldap.bloodysearch(base, filter, ...)
for entry in entries:
    other_entries = conn.ldap.bloodysearch(entry["dn"], ...)
    for other_entry in other_entries:
        process(other_entry)

# After
ldap = await conn.ldap
entries = ldap.bloodysearch(base, filter, ...)
async for entry in entries:
    other_entries = ldap.bloodysearch(entry["dn"], ...)
    async for other_entry in other_entries:
        process(other_entry)
```

## Testing After Conversion

### Unit Tests
Run existing tests to ensure no regressions:
```bash
python -m pytest tests/
```

### Manual Testing
Test each converted function:
```bash
# Get operations
bloodyAD --host dc.domain.local --username user --password pass get object Administrator

# Add operations  
bloodyAD --host dc.domain.local --username user --password pass add groupMember "Group" "User"

# Set operations
bloodyAD --host dc.domain.local --username user --password pass set password "User" "NewPass"

# Remove operations
bloodyAD --host dc.domain.local --username user --password pass remove groupMember "Group" "User"
```

## Common Issues and Solutions

### Issue: "coroutine was never awaited"
**Solution**: Add `await` before the async function call

### Issue: "object async_generator can't be used in 'await' expression"
**Solution**: Use `async for` instead of `await` for generators

### Issue: "TypeError: 'async_generator' object is not an iterator"
**Solution**: Use `async for` to iterate, not `for` or `next()`

### Issue: AttributeError on conn.ldap
**Solution**: Make sure to `await conn.ldap` first and use the result

## File Structure After Refactoring

```
bloodyAD/
├── main.py                 [✓ Converted]
├── network/
│   ├── config.py          [✓ Converted]
│   └── ldap.py            [✓ Converted]
├── utils.py               [✓ Converted]
└── cli_modules/
    ├── get.py             [✓ Converted]
    ├── set.py             [✓ Converted]
    ├── add.py             [⚠ Partial - 11 functions remain]
    └── remove.py          [⚠ Not started - 8 functions]
```

## Next Steps

1. Convert remaining add.py functions (use pattern above)
2. Convert remaining remove.py functions (use pattern above)
3. Run tests to validate changes
4. Update any documentation that references the old API
5. Consider adding type hints for async functions
