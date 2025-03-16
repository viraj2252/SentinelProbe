# Custom Rule Development

This guide explains how to create and implement custom rules for the SentinelProbe AI Decision Engine, allowing you to extend the system's capabilities and tailor it to your specific testing needs.

## Understanding Rules

Rules are the foundation of SentinelProbe's decision-making system. Each rule consists of:

- **Conditions**: Criteria that must be met for the rule to trigger
- **Actions**: Operations to perform when conditions are met
- **Metadata**: Additional information about the rule, including priority and severity

Rules are categorized by type (service detection, vulnerability scanning, exploitation, etc.) and evaluated in order of priority.

## Rule Structure

A typical rule in SentinelProbe has the following structure:

```python
{
    "name": "Detect MySQL Service",
    "description": "Identifies MySQL database services for vulnerability scanning",
    "rule_type": "service_detection",
    "severity": "medium",
    "conditions": {
        "condition_type": "service_detected",
        "service_type": "mysql"
    },
    "actions": {
        "action_type": "update_knowledge",
        "knowledge_key": "services.mysql",
        "knowledge_value": {
            "service_type": "mysql",
            "needs_scanning": true,
            "default_port": 3306
        }
    },
    "is_active": true,
    "priority": 50,
    "metadata": {
        "author": "SentinelProbe Team",
        "created_date": "2023-03-15",
        "tags": ["database", "mysql"]
    }
}
```

## Rule Types

SentinelProbe supports several rule types, each serving a specific purpose:

1. **SERVICE_DETECTION**: Rules for identifying services on target systems
2. **VULNERABILITY_SCAN**: Rules for determining what and how to scan
3. **EXPLOITATION**: Rules for selecting and configuring exploit attempts
4. **POST_EXPLOITATION**: Rules for post-exploitation activities
5. **REPORTING**: Rules for customizing report generation
6. **CORRELATION**: Rules for identifying relationships between vulnerabilities
7. **ADAPTIVE**: Rules that can learn and evolve based on feedback

## Condition Types

Conditions define when a rule should trigger. Common condition types include:

### Service Detection Conditions

```python
{
    "condition_type": "service_detected",
    "service_type": "http"
}
```

### Port-Based Conditions

```python
{
    "condition_type": "port_open",
    "port_number": 22,
    "protocol": "tcp"
}
```

### Multiple Conditions with AND Logic

```python
{
    "condition_type": "and",
    "conditions": [
        {
            "condition_type": "service_detected",
            "service_type": "http"
        },
        {
            "condition_type": "port_open",
            "port_number": 443
        }
    ]
}
```

### OS-Specific Conditions

```python
{
    "condition_type": "os_detected",
    "os_type": "windows",
    "version": "server_2019"
}
```

### Vulnerability-Based Conditions

```python
{
    "condition_type": "vulnerability_detected",
    "vulnerability_type": "sql_injection",
    "severity": "high"
}
```

## Action Types

Actions define what happens when a rule's conditions are met:

### Knowledge Update Actions

```python
{
    "action_type": "update_knowledge",
    "knowledge_key": "services.web.vulnerable",
    "knowledge_value": {
        "has_vulnerability": true,
        "vulnerability_type": "sql_injection"
    }
}
```

### Scan Triggering Actions

```python
{
    "action_type": "trigger_scan",
    "scan_type": "web_application",
    "scan_parameters": {
        "depth": "comprehensive",
        "authentication": false
    }
}
```

### Exploitation Actions

```python
{
    "action_type": "attempt_exploit",
    "exploit_module": "sql_injection_auth_bypass",
    "exploit_parameters": {
        "target_url": "{target.url}",
        "login_page": "/login.php"
    }
}
```

### Strategy Creation Actions

```python
{
    "action_type": "create_strategy",
    "strategy_name": "Web App Testing",
    "strategy_phase": "vulnerability_scan",
    "strategy_parameters": {
        "scan_sequence": ["xss", "sql_injection", "csrf"]
    }
}
```

## Creating Custom Rules

### Method 1: Using the API

```python
import requests
import json

# Define your rule
rule = {
    "name": "Custom SSL/TLS Detection",
    "description": "Identifies outdated SSL/TLS configurations",
    "rule_type": "vulnerability_scan",
    "severity": "high",
    "conditions": {
        "condition_type": "service_detected",
        "service_type": "https"
    },
    "actions": {
        "action_type": "trigger_scan",
        "scan_type": "ssl_tls",
        "scan_parameters": {
            "check_heartbleed": True,
            "check_beast": True,
            "check_poodle": True
        }
    },
    "is_active": True,
    "priority": 40,
    "metadata": {
        "author": "Your Name",
        "tags": ["ssl", "tls", "encryption"]
    }
}

# Create the rule
response = requests.post(
    "http://localhost:8000/api/ai-decision/rules",
    headers={"Content-Type": "application/json"},
    data=json.dumps(rule)
)

print(response.json())
```

### Method 2: Using Configuration Files

Create a YAML file with your rules:

```yaml
# custom_rules.yaml
rules:
  - name: "MongoDB Detection"
    description: "Identifies MongoDB instances and configures scanning"
    rule_type: "service_detection"
    severity: "medium"
    conditions:
      condition_type: "port_open"
      port_number: 27017
      protocol: "tcp"
    actions:
      action_type: "update_knowledge"
      knowledge_key: "services.mongodb"
      knowledge_value:
        service_type: "mongodb"
        needs_scanning: true
        default_port: 27017
    is_active: true
    priority: 45
    metadata:
      author: "Your Name"
      tags: ["database", "mongodb", "nosql"]
```

Then import the rules:

```bash
python -m sentinelprobe rules import --file custom_rules.yaml
```

### Method 3: Programmatically via Python

```python
from sentinelprobe.ai_decision.models import DecisionRuleCreate, DecisionRuleType, DecisionRuleSeverity
from sentinelprobe.ai_decision.repository import DecisionRuleRepository
from sentinelprobe.core.db import get_session

async def create_custom_rule():
    async with get_session() as session:
        repo = DecisionRuleRepository(session)

        # Define rule
        rule_data = DecisionRuleCreate(
            name="Redis Security Check",
            description="Detects Redis instances and tests for security misconfigurations",
            rule_type=DecisionRuleType.VULNERABILITY_SCAN,
            severity=DecisionRuleSeverity.HIGH,
            conditions={
                "condition_type": "service_detected",
                "service_type": "redis"
            },
            actions={
                "action_type": "trigger_scan",
                "scan_type": "redis_security",
                "scan_parameters": {
                    "check_authentication": True,
                    "check_public_access": True,
                    "check_version": True
                }
            },
            is_active=True,
            priority=35,
            metadata={
                "author": "Your Name",
                "tags": ["database", "redis", "cache"]
            }
        )

        # Create rule
        rule = await repo.create_rule(rule_data)
        print(f"Created rule with ID: {rule.id}")

# Run the async function
import asyncio
asyncio.run(create_custom_rule())
```

## Creating Adaptive Rules

Adaptive rules can learn and evolve based on feedback from testing results:

```python
from sentinelprobe.ai_decision.models import AdaptiveRuleCreate, DecisionRuleType, DecisionRuleSeverity, ConfidenceLevel
from sentinelprobe.ai_decision.repository import AdaptiveRuleRepository
from sentinelprobe.core.db import get_session

async def create_adaptive_rule():
    async with get_session() as session:
        repo = AdaptiveRuleRepository(session)

        # Define adaptive rule
        rule_data = AdaptiveRuleCreate(
            name="Adaptive Web Scanner Selection",
            description="Adaptively selects the best scanner based on historical results",
            rule_type=DecisionRuleType.VULNERABILITY_SCAN,
            conditions={
                "condition_type": "service_detected",
                "service_type": "http"
            },
            actions={
                "action_type": "select_scanner",
                "scanner_options": [
                    {"name": "fast_scan", "weight": 0.3},
                    {"name": "comprehensive_scan", "weight": 0.7}
                ],
                "selection_method": "weighted_random"
            },
            confidence=ConfidenceLevel.MEDIUM,
            is_active=True,
            metadata={
                "learning_rate": 0.1,
                "initial_weights": {
                    "fast_scan": 0.3,
                    "comprehensive_scan": 0.7
                }
            }
        )

        # Create adaptive rule
        rule = await repo.create_adaptive_rule(rule_data)
        print(f"Created adaptive rule with ID: {rule.id}")

# Run the async function
import asyncio
asyncio.run(create_adaptive_rule())
```

## Creating Correlation Rules

Correlation rules detect relationships between multiple vulnerabilities:

```python
from sentinelprobe.ai_decision.models import VulnerabilityCorrelationCreate, ConfidenceLevel, ContextType
from sentinelprobe.ai_decision.repository import VulnerabilityCorrelationRepository
from sentinelprobe.core.db import get_session

async def create_correlation_rule():
    async with get_session() as session:
        repo = VulnerabilityCorrelationRepository(session)

        # Define correlation rule
        rule_data = VulnerabilityCorrelationCreate(
            name="Web App + Database Correlation",
            description="Detects when web application vulnerabilities can be combined with database issues",
            pattern_type="composite_attack",
            pattern_definition={
                "required_vulnerabilities": [
                    {
                        "type": "sql_injection",
                        "confidence_min": 0.7
                    },
                    {
                        "type": "weak_database_credentials",
                        "confidence_min": 0.6
                    }
                ],
                "max_distance": 2,  # Logical distance between vulnerabilities
                "time_window": 3600  # Time window in seconds
            },
            severity_adjustment=1.5,  # Increase severity by 1.5x when pattern matches
            confidence=ConfidenceLevel.HIGH,
            context_type=ContextType.APPLICATION,
            is_active=True,
            metadata={
                "author": "Your Name",
                "tags": ["web", "database", "composite", "critical-path"]
            }
        )

        # Create correlation rule
        rule = await repo.create_vulnerability_correlation(rule_data)
        print(f"Created correlation rule with ID: {rule.id}")

# Run the async function
import asyncio
asyncio.run(create_correlation_rule())
```

## Testing Custom Rules

After creating custom rules, it's important to test them to ensure they work as expected:

### Using Rule Simulation

```bash
# Test a rule against sample data
python -m sentinelprobe rules simulate --rule-id 42 --target-file sample_target.json
```

### Using Standalone Test Jobs

```bash
# Create a job with specific rule testing
python -m sentinelprobe job create --target 192.168.56.101 --name "Rule Test" --test-rules 42,43,44
```

## Best Practices for Custom Rules

### 1. Start Simple

Begin with simple rules focused on specific technologies or vulnerabilities you understand well. Build complexity gradually as you gain confidence.

### 2. Use Descriptive Names and Documentation

Make your rule names clear and descriptive. Provide detailed descriptions that explain what the rule does and when it should be used.

### 3. Prioritize Appropriately

Set appropriate priorities to ensure rules are evaluated in a logical order. More specific rules should generally have higher priority than general rules.

### 4. Test Thoroughly

Always test your rules against known scenarios before using them in production. Use rule simulation to verify behavior.

### 5. Implement Feedback Loops

For adaptive rules, ensure you have mechanisms to provide feedback on rule effectiveness. This enables the learning process.

### 6. Control Rule Propagation

When creating rules that generate other rules or strategies, be careful to avoid unintended cascades or loops.

### 7. Document Side Effects

Clearly document any side effects your rules may have, such as modifying the knowledge base or triggering scans.

## Troubleshooting Custom Rules

### Rule Not Triggering

1. Verify the rule conditions match your target system's state
2. Check the rule priority to ensure it's being evaluated
3. Confirm the rule is active
4. Review logs for evaluation details

### Rule Triggering Unexpectedly

1. Check for overly broad conditions
2. Verify the knowledge base state
3. Look for conflicting rules with higher priority

### Rule Actions Not Working

1. Ensure action parameters are correct
2. Check for required permissions
3. Verify the action type is supported
4. Review service availability for triggered scans

## Advanced Topics

### Rule Chaining

Rules can be chained together by having one rule update the knowledge base, which triggers another rule:

```python
# Rule 1: Detect service
{
    "name": "Detect MSSQL Service",
    "conditions": {...},
    "actions": {
        "action_type": "update_knowledge",
        "knowledge_key": "services.mssql",
        "knowledge_value": {"detected": true}
    }
}

# Rule 2: Triggered by knowledge from Rule 1
{
    "name": "Scan MSSQL Service",
    "conditions": {
        "condition_type": "knowledge_check",
        "knowledge_key": "services.mssql.detected",
        "expected_value": true
    },
    "actions": {
        "action_type": "trigger_scan",
        "scan_type": "mssql_security"
    }
}
```

### Context-Aware Rules

Rules can use the target context to make more informed decisions:

```python
{
    "name": "High-Risk Target SQL Injection Check",
    "conditions": {
        "condition_type": "and",
        "conditions": [
            {
                "condition_type": "service_detected",
                "service_type": "http"
            },
            {
                "condition_type": "target_risk_level",
                "risk_level": "high"
            }
        ]
    },
    "actions": {
        "action_type": "trigger_scan",
        "scan_type": "sql_injection",
        "scan_parameters": {
            "depth": "exhaustive"
        }
    }
}
```

### Rule Templates

You can create rule templates to simplify creation of similar rules:

```python
def create_service_detection_rule(service_name, port=None, priority=50):
    """Create a standard service detection rule."""
    conditions = {
        "condition_type": "service_detected",
        "service_type": service_name
    }

    if port:
        conditions = {
            "condition_type": "and",
            "conditions": [
                conditions,
                {
                    "condition_type": "port_open",
                    "port_number": port
                }
            ]
        }

    return {
        "name": f"Detect {service_name.upper()} Service",
        "description": f"Identifies {service_name} services for vulnerability scanning",
        "rule_type": "service_detection",
        "severity": "medium",
        "conditions": conditions,
        "actions": {
            "action_type": "update_knowledge",
            "knowledge_key": f"services.{service_name}",
            "knowledge_value": {
                "service_type": service_name,
                "needs_scanning": True,
                "default_port": port
            }
        },
        "is_active": True,
        "priority": priority
    }

# Use the template
ssh_rule = create_service_detection_rule("ssh", 22, 45)
ftp_rule = create_service_detection_rule("ftp", 21, 46)
```

## Further Learning

- [AI Decision Engine Documentation](../components/ai-decision-engine.md)
- [API Reference](api-reference.md)
- [Integration Guide](integration.md)
- [Example Rule Repository](https://github.com/yourusername/sentinelprobe-custom-rules)
