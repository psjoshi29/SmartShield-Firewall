"""RuleSet management: ordering, priorities, duplication checking, and CRUD operations."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from smartshield.engine.models import Action, Rule
from smartshield.engine.validator import RuleValidationError, validate_action, validate_rule


class RuleSet:
    """Manages an ordered collection of firewall security rules and fallback policy."""

    def __init__(self, rules: Optional[List[Rule]] = None, default_action: Action = Action.BLOCK) -> None:
        self.default_action: Action = default_action
        self._rules: List[Rule] = []
        if rules:
            for r in rules:
                self.add_rule(r)

    @property
    def rules(self) -> List[Rule]:
        """Return all rules ordered by priority (ascending: 1 = highest)."""
        return list(self._rules)

    def add_rule(self, rule: Rule) -> None:
        """Add a validated rule. Rejects duplicate IDs and sorts by priority."""
        validated = validate_rule(rule)
        if any(r.id == validated.id for r in self._rules):
            raise RuleValidationError(f"Rule with ID '{validated.id}' already exists.")
        self._rules.append(validated)
        self._sort_rules()

    def update_rule(self, rule_id: str, updated: Rule) -> None:
        """Update an existing rule in-place and re-sort."""
        validated = validate_rule(updated)
        for idx, existing in enumerate(self._rules):
            if existing.id == rule_id:
                if validated.id != rule_id and any(r.id == validated.id for r in self._rules):
                    raise RuleValidationError(f"Cannot rename rule ID to already existing '{validated.id}'.")
                self._rules[idx] = validated
                self._sort_rules()
                return
        raise KeyError(f"Rule with ID '{rule_id}' not found.")

    def delete_rule(self, rule_id: str) -> bool:
        """Remove a rule by its identifier."""
        initial_len = len(self._rules)
        self._rules = [r for r in self._rules if r.id != rule_id]
        return len(self._rules) < initial_len

    def get_rule(self, rule_id: str) -> Optional[Rule]:
        """Find a rule by its ID."""
        for r in self._rules:
            if r.id == rule_id:
                return r
        return None

    def toggle_rule(self, rule_id: str, enabled: Optional[bool] = None) -> bool:
        """Toggle or explicitly set enabled status for a rule."""
        target = self.get_rule(rule_id)
        if not target:
            raise KeyError(f"Rule with ID '{rule_id}' not found.")
        target.enabled = not target.enabled if enabled is None else enabled
        return target.enabled

    def reorder_rules(self, rule_ids_in_order: List[str]) -> None:
        """Reassign priorities based on ordered list of rule IDs (multiples of 10)."""
        rule_map = {r.id: r for r in self._rules}
        if set(rule_ids_in_order) != set(rule_map.keys()):
            raise ValueError("Provided list of rule IDs does not match existing rules.")

        for rank, r_id in enumerate(rule_ids_in_order, start=1):
            rule_map[r_id].priority = rank * 10
        self._sort_rules()

    def set_default_action(self, action: Action) -> None:
        """Configure default fallback action when no rules match."""
        self.default_action = validate_action(action)

    def get_active_rules(self) -> List[Rule]:
        """Get only enabled rules in evaluation order."""
        return [r for r in self._rules if r.enabled]

    def _sort_rules(self) -> None:
        """Sort rules ascending by priority; ties broken deterministically by ID."""
        self._rules.sort(key=lambda r: (r.priority, r.id))

    def to_dict(self) -> Dict[str, Any]:
        """Serialize ruleset to dictionary."""
        return {
            "default_action": self.default_action.value,
            "rules": [r.to_dict() for r in self._rules],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> RuleSet:
        """Instantiate ruleset from dictionary."""
        default_act = Action.from_str(str(data.get("default_action", "BLOCK")))
        rules_data = data.get("rules", [])
        rules: List[Rule] = []
        for rd in rules_data:
            rules.append(Rule.from_dict(rd))
        return cls(rules=rules, default_action=default_act)
