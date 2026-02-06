# AD Enumeration Tool - OpSec Features Guide

## Stealth Mode Overview

The tool now includes operational security (OpSec) features for red team engagements. These features help blend enumeration traffic with normal AD activity to avoid detection.

## Stealth Features

### 1. **Rate Limiting**
- Configurable queries per minute (default: 15 QPM)
- Prevents volume-based detection alerts
- Mimics normal user/application behavior

### 2. **Intelligent Delays**
- Random delays between queries (default: 2-8 seconds)
- Jitter adds 30% variance to delays
- Avoids predictable timing patterns

### 3. **Traffic Blending**
- Smaller LDAP page sizes (100 vs 1000)
- Randomized query order
- Natural connection patterns

### 4. **Time Spreading**
- Spread enumeration over hours/days
- Configurable duration
- Gradual data collection

## Usage Examples

### Basic Stealth Mode
```bash
# Enable stealth with defaults (2-8s delay, 15 QPM, 100 page size)
python ad_enum_tool.py -d example.com -u admin -p password -t 192.168.1.10 --stealth
```

### Custom Timing
```bash
# Slower, more cautious enumeration
python ad_enum_tool.py -d example.com -u admin -p password -t 192.168.1.10 \
  --stealth --delay-min 5 --delay-max 15 --max-qpm 5
```

### Extended Duration
```bash
# Spread enumeration over 6 hours
python ad_enum_tool.py -d example.com -u admin -p password -t 192.168.1.10 \
  --stealth --spread-hours 6
```

### Combined OpSec
```bash
# Multi-day stealthy enumeration with HTML report
python ad_enum_tool.py -d example.com -u admin -p password -t 192.168.1.10 \
  --stealth \
  --delay-min 10 --delay-max 30 \
  --max-qpm 3 \
  --spread-hours 48 \
  --output-html stealth_report.html
```

## Configuration (config.py)

Edit `config.py` to set default stealth behavior:

```python
STEALTH_SETTINGS = {
    'enabled': True,                     # Enable by default
    'query_delay_min': 5.0,              # Slower enumeration
    'query_delay_max': 15.0,             # More variation
    'jitter_enabled': True,              # Add randomness
    'jitter_percentage': 30,             # 30% jitter
    'max_queries_per_minute': 5,         # Very conservative
    'page_size_stealth': 50,             # Even smaller pages
    'randomize_query_order': True,       # Randomize order
    'spread_enumeration_hours': 12,      # Default 12-hour spread
}
```

## OpSec Comparison

| Mode | Speed | Detection Risk | Use Case |
|------|-------|----------------|----------|
| **Normal** | Fast | High | Authorized assessment, time-limited |
| **Stealth (Basic)** | Medium | Medium | Red team, moderate stealth |
| **Stealth (Slow)** | Slow | Low | Long-term red team, high stealth |
| **Extended** | Very Slow | Very Low | Multi-day/week operations |

## Session Statistics

Stealth mode provides detailed statistics:
```
[*] Stealth Session Statistics:
    Total Queries: 245
    Session Duration: 1:23:45
    Avg Queries/Min: 2.9
```

## Best Practices

### For Standard Assessments
```bash
# Fast enumeration (no stealth)
python ad_enum_tool.py -d example.com -u admin -p password -t 192.168.1.10 --full-enum
```

### For Red Team Engagements
```bash
# Balanced stealth
python ad_enum_tool.py -d example.com -u admin -p password -t 192.168.1.10 \
  --stealth --spread-hours 8
```

### For Long-Term Operations
```bash
# Maximum stealth (multi-day)
python ad_enum_tool.py -d example.com -u admin -p password -t 192.168.1.10 \
  --stealth --delay-min 20 --delay-max 60 --max-qpm 2 --spread-hours 72
```

## What Stealth Mode Does

✅ **Implements:**
- Rate limiting to avoid volume alerts
- Random delays to avoid pattern detection
- Smaller query sizes to blend with normal traffic
- Query randomization to avoid predictable behavior
- Time-spreading for long-duration operations

❌ **Does NOT implement:**
- Code obfuscation
- Signature evasion
- Process hiding
- Log tampering

## Detection Considerations

Even with stealth mode:
- LDAP queries are still logged
- Authentication events are still recorded
- Network traffic can still be analyzed
- Baselines may detect unusual enumeration

**Stealth mode reduces detection probability but doesn't eliminate it.**

## Recommendation

- **Pentest/Audit**: Use normal mode (faster, complete coverage)
- **Red Team**: Use stealth mode (simulates real attacker behavior)
- **Purple Team**: Test both modes to validate detection capabilities

---

*Stealth features are for authorized red team operations only.*
