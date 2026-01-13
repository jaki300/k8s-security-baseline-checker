package core

import (
	"fmt"
	"sync"
)

// DefaultPluginRegistry is the default implementation of PluginRegistry
type DefaultPluginRegistry struct {
	checkers         map[string]Checker
	complianceMappers map[string]ComplianceMapper
	mu               sync.RWMutex
}

// NewPluginRegistry creates a new plugin registry
func NewPluginRegistry() PluginRegistry {
	return &DefaultPluginRegistry{
		checkers:          make(map[string]Checker),
		complianceMappers: make(map[string]ComplianceMapper),
	}
}

// RegisterChecker registers a new checker plugin
func (r *DefaultPluginRegistry) RegisterChecker(checker Checker) error {
	if checker == nil {
		return fmt.Errorf("checker cannot be nil")
	}

	if checker.ID() == "" {
		return fmt.Errorf("checker ID cannot be empty")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.checkers[checker.ID()]; exists {
		return fmt.Errorf("checker with ID '%s' is already registered", checker.ID())
	}

	r.checkers[checker.ID()] = checker
	return nil
}

// RegisterComplianceMapper registers a new compliance mapper
func (r *DefaultPluginRegistry) RegisterComplianceMapper(mapper ComplianceMapper) error {
	if mapper == nil {
		return fmt.Errorf("compliance mapper cannot be nil")
	}

	if mapper.Framework() == "" {
		return fmt.Errorf("framework name cannot be empty")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.complianceMappers[mapper.Framework()]; exists {
		return fmt.Errorf("compliance mapper for framework '%s' is already registered", mapper.Framework())
	}

	r.complianceMappers[mapper.Framework()] = mapper
	return nil
}

// GetChecker retrieves a checker by ID
func (r *DefaultPluginRegistry) GetChecker(id string) (Checker, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	checker, exists := r.checkers[id]
	if !exists {
		return nil, fmt.Errorf("checker with ID '%s' not found", id)
	}

	return checker, nil
}

// GetComplianceMapper retrieves a compliance mapper by framework
func (r *DefaultPluginRegistry) GetComplianceMapper(framework string) (ComplianceMapper, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	mapper, exists := r.complianceMappers[framework]
	if !exists {
		return nil, fmt.Errorf("compliance mapper for framework '%s' not found", framework)
	}

	return mapper, nil
}

// ListCheckers returns all registered checkers
func (r *DefaultPluginRegistry) ListCheckers() []Checker {
	r.mu.RLock()
	defer r.mu.RUnlock()

	checkers := make([]Checker, 0, len(r.checkers))
	for _, checker := range r.checkers {
		checkers = append(checkers, checker)
	}

	return checkers
}

// ListComplianceMappers returns all registered compliance mappers
func (r *DefaultPluginRegistry) ListComplianceMappers() []ComplianceMapper {
	r.mu.RLock()
	defer r.mu.RUnlock()

	mappers := make([]ComplianceMapper, 0, len(r.complianceMappers))
	for _, mapper := range r.complianceMappers {
		mappers = append(mappers, mapper)
	}

	return mappers
}
