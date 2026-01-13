# Checker Engine

The checker engine provides a plugin-based architecture for executing security checks.

## Architecture

The checker engine uses a plugin-based architecture where different checkers can be registered and executed dynamically. This allows for:

- **Extensibility**: New checkers can be added without modifying core code
- **Modularity**: Each checker is independent and can be developed separately
- **Flexibility**: Different checkers can handle different types of checks (K8s, Cloud, etc.)

## Core Components

### Checker Interface

All checkers must implement the `Checker` interface:

```go
type Checker interface {
    Name() string
    Type() string
    Execute(ctx context.Context, check types.Check, options *ExecutionOptions) (*types.Result, error)
    Validate(check types.Check) bool
}
```

### Engine

The `Engine` manages registered checkers and executes checks:

- **Register**: Add a new checker to the engine
- **ExecuteCheck**: Execute a single check using the appropriate checker
- **ExecuteChecks**: Execute multiple checks (sequentially or in parallel)
- **ExecuteBenchmark**: Execute all checks from a benchmark

### BaseChecker

`BaseChecker` provides a base implementation that can be embedded by specific checkers to reduce boilerplate code.

## Usage Example

```go
// Create engine
engine := checker.NewEngine(logger)

// Register a checker
k8sChecker := &K8sChecker{...}
engine.Register(k8sChecker)

// Execute a check
result, err := engine.ExecuteCheck(ctx, check, options)

// Execute a benchmark
report, err := engine.ExecuteBenchmark(ctx, benchmark, options, true)
```

## Creating a Custom Checker

1. Implement the `Checker` interface or embed `BaseChecker`:

```go
type MyChecker struct {
    *checker.BaseChecker
    // Your custom fields
}

func NewMyChecker(logger *logrus.Logger) *MyChecker {
    base := checker.NewBaseChecker("my-checker", "my-type", logger)
    return &MyChecker{
        BaseChecker: base,
    }
}

func (c *MyChecker) Execute(ctx context.Context, check types.Check, options *checker.ExecutionOptions) (*types.Result, error) {
    // Your check logic here
    if /* check passes */ {
        return c.CreatePassResult(check, "Check passed"), nil
    }
    return c.CreateFailResult(check, []string{"resource1", "resource2"}, "Check failed"), nil
}
```

2. Register your checker:

```go
engine.Register(NewMyChecker(logger))
```

## Execution Options

The `ExecutionOptions` struct allows passing context to checkers:

- `Namespaces`: Filter checks to specific namespaces
- `ClusterInfo`: Cluster context information
- `Config`: Additional configuration
- `Logger`: Logger instance

