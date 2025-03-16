# AI Decision Engine

The AI Decision Engine is the intelligent core of the SentinelProbe system, responsible for analyzing data, making strategic decisions, and adapting testing strategies based on discovered information.

## Overview

The AI Decision Engine uses a hybrid approach combining rule-based systems and machine learning to make intelligent decisions throughout the penetration testing process. It continuously learns and improves from testing results, adapting its strategies for more effective vulnerability detection.

## Key Capabilities

### 1. Rule-based Decision Framework

The core decision-making system relies on a flexible rule-based framework that evaluates conditions and triggers actions based on the current state of knowledge about target systems.

Key features:

- Extensible rule conditions and actions
- Priority-based rule evaluation
- Rule categorization by type (service detection, vulnerability scanning, exploitation, etc.)
- Rule severity classification (low, medium, high, critical)

### 2. Knowledge Representation

The system maintains a structured knowledge base that stores all discovered information about target systems, providing a foundation for decision-making.

Key features:

- Flexible key-value storage with type information
- Support for various data types (string, integer, float, boolean, JSON)
- Confidence levels for stored information
- Target-specific and global knowledge items

### 3. Strategy Formulation

Based on available knowledge and rule evaluations, the engine formulates testing strategies across different phases of the penetration testing lifecycle.

Key features:

- Phase-specific strategy generation
- Strategy prioritization
- Detailed parameter specification for testing actions
- Dynamic strategy adjustment based on new discoveries

### 4. Advanced Correlation Analysis

The engine can identify relationships between multiple vulnerabilities to detect compound risks that may not be evident when considering vulnerabilities in isolation.

Key features:

- Pattern-based vulnerability correlation
- Severity adjustment based on correlation findings
- Context-aware analysis (infrastructure, application, data, user, business)
- Confidence scoring for correlation results

### 5. Contextual Scoring

Vulnerabilities are scored and prioritized based on their context within the specific environment, adjusting standard severity scores to reflect actual risk.

Key features:

- Environment-specific risk adjustment
- Custom scoring functions for different context types
- Integration with standard scoring systems (e.g., CVSS)
- Prioritization based on business impact

### 6. Adaptive Rule Learning

The system continuously learns from testing results, evolving its decision rules to improve effectiveness over time.

Key features:

- Success/failure tracking for rules
- Effectiveness scoring
- Automatic rule evolution for underperforming rules
- Version control for rule modifications

### 7. Reinforcement Learning

The engine employs reinforcement learning techniques to optimize testing strategies, rewarding successful approaches and penalizing ineffective ones.

Key features:

- Strategy success measurement
- Reward-based learning
- Testing path optimization
- Continuous improvement of decision processes

## Architecture

The AI Decision Engine consists of several interconnected components:

### Models

- `DecisionRule`: Defines conditions and actions for decision making
- `KnowledgeItem`: Stores discovered information
- `TestStrategy`: Defines testing approaches for different phases
- `VulnerabilityCorrelation`: Defines patterns for correlating vulnerabilities
- `AdaptiveRule`: Extends DecisionRule with learning capabilities
- `ContextualScore`: Defines scoring adjustments based on context

### Repositories

- `KnowledgeRepository`: Manages knowledge storage and retrieval
- `DecisionRuleRepository`: Manages rule CRUD operations
- `TestStrategyRepository`: Manages strategy creation and updates
- `VulnerabilityCorrelationRepository`: Manages correlation patterns
- `AdaptiveRuleRepository`: Manages adaptive rules with learning capabilities

### Services

- `DecisionEngineService`: Core service implementing the decision logic
  - Rule evaluation and execution
  - Strategy generation
  - Knowledge processing
  - Adaptive learning

## Interacting with the AI Decision Engine

### Via API

The AI Decision Engine exposes RESTful API endpoints for interaction:

```
POST /api/ai-decision/rules - Create a new decision rule
GET /api/ai-decision/rules - List decision rules
GET /api/ai-decision/rules/{id} - Get a specific rule
PUT /api/ai-decision/rules/{id} - Update a rule
DELETE /api/ai-decision/rules/{id} - Delete a rule

POST /api/ai-decision/knowledge - Store knowledge item
GET /api/ai-decision/knowledge - Query knowledge base
...
```

### Via Configuration

Rules can also be defined via configuration files:

```yaml
# Example decision rule configuration
rules:
  - name: "Detect SSH Services"
    description: "Identify SSH services for vulnerability scanning"
    rule_type: "service_detection"
    severity: "medium"
    conditions:
      condition_type: "service_detected"
      service_type: "ssh"
    actions:
      action_type: "update_knowledge"
      knowledge_key: "services.ssh"
      knowledge_value:
        service_type: "ssh"
        needs_scanning: true
    is_active: true
    priority: 50
```

## Configuring the AI Decision Engine

### Rule Configuration

Rules can be configured through the API, configuration files, or the database. Key aspects to configure:

1. Rule conditions - What triggers the rule
2. Rule actions - What happens when conditions are met
3. Rule priority - Order of evaluation
4. Rule severity - Impact level of the rule

### Knowledge Management

The knowledge base can be:

1. Pre-populated with known information
2. Updated dynamically during testing
3. Queried for decision-making
4. Exported for analysis

### Strategy Configuration

Strategies define how testing proceeds and can be configured:

1. Default strategies for different phases
2. Custom strategies for specific target types
3. Strategy priorities and dependencies

### Correlation Pattern Configuration

Vulnerability correlation patterns can be defined:

1. Pattern types and definitions
2. Severity adjustments
3. Context type specifications

## Extending the AI Decision Engine

### Creating Custom Rules

You can create custom rules to address specific testing scenarios:

```python
# Example of creating a custom rule via the API
rule_data = DecisionRuleCreate(
    name="Custom Web App Rule",
    description="Detect and scan web applications",
    rule_type=DecisionRuleType.VULNERABILITY_SCAN,
    severity=DecisionRuleSeverity.HIGH,
    conditions={
        "condition_type": "service_detected",
        "service_type": "http"
    },
    actions={
        "action_type": "scan_service",
        "scan_type": "web_app",
        "scan_params": {
            "depth": "comprehensive",
            "auth_required": True
        }
    },
    priority=30
)

# Using the API client
api_client.create_decision_rule(rule_data)
```

### Developing Custom Learning Models

Advanced users can implement custom learning models by:

1. Extending the `AdaptiveRule` class
2. Creating custom reinforcement learning algorithms
3. Implementing specialized score functions

## Monitoring and Debugging

### Logging

The AI Decision Engine provides comprehensive logging:

```
DEBUG:ai_decision:Evaluating rule 'Detect SSH Services' (id=42)
INFO:ai_decision:Rule matched, executing action 'update_knowledge'
WARNING:ai_decision:Rule execution failed: Invalid knowledge key format
```

### Metrics

Key metrics are available for monitoring:

1. Rule evaluation counts and success rates
2. Strategy generation times
3. Knowledge base size and query performance
4. Learning algorithm performance

### Visualization

The web interface provides visualizations:

1. Decision trees showing rule evaluations
2. Knowledge graphs displaying relationships
3. Strategy effectiveness charts
4. Learning progress over time

## Best Practices

### Rule Design

1. Create specific, focused rules rather than complex multi-condition rules
2. Establish a clear hierarchy of rules with appropriate priorities
3. Start with conservative actions and gradually increase aggressiveness
4. Document rule purpose and expected outcomes

### Knowledge Management

1. Use consistent key naming conventions
2. Set appropriate confidence levels for knowledge items
3. Regularly clean up outdated knowledge
4. Validate knowledge from multiple sources when possible

### Learning Configuration

1. Start with small learning rates
2. Monitor rule effectiveness and evolution
3. Periodically review and prune ineffective adaptive rules
4. Maintain a baseline of known-good rules

## Troubleshooting

### Common Issues

1. **Rules not firing**: Check rule conditions, priorities, and activation status
2. **Incorrect decisions**: Review knowledge base for inaccurate information
3. **Poor learning performance**: Evaluate feedback mechanisms and learning parameters
4. **Slow rule evaluation**: Optimize rule conditions and reduce rule count

### Diagnostic Tools

1. Rule evaluation tracing
2. Knowledge base inspection
3. Strategy simulation
4. Learning path visualization

## Advanced Topics

### Integration with External Intelligence Sources

The AI Decision Engine can integrate with:

1. Threat intelligence feeds
2. Vulnerability databases
3. Attack pattern repositories
4. Industry-specific knowledge bases

### Multi-target Strategy Optimization

For complex environments:

1. Dependency mapping between targets
2. Resource allocation optimization
3. Attack path analysis
4. Network-wide risk assessment

## API Reference

See the [AI Decision Engine API Reference](../advanced/api-reference.md#ai-decision-engine) for complete API documentation.
