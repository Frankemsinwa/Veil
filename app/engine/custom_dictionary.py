"""Enterprise Custom Entity Dictionary & Blacklist Engine.

Enables organizations to define proprietary codenames, client names,
internal project keys, and custom regex rules for automatic fail-closed
blocking or reversible session tokenization.
"""
import re
import json
import time
import uuid
import logging
from pathlib import Path
from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field

from app.core.config import settings
from app.engine.models import DetectedSpan, EntityCategory, EntityType

logger = logging.getLogger("veil.custom_dictionary")


class CustomEntityRule(BaseModel):
    """Configuration rule for an enterprise custom entity or blacklisted phrase."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    name: str = Field(description="Descriptive name (e.g. 'Project Titan', 'Customer Acme')")
    pattern: str = Field(description="Literal word/phrase or regular expression")
    is_regex: bool = Field(default=False, description="Whether pattern is a regular expression")
    case_sensitive: bool = Field(default=False, description="Match case sensitivity")
    placeholder_prefix: str = Field(default="CONFIDENTIAL", description="Prefix for vault placeholders (e.g. PROJECT, CLIENT)")
    action: str = Field(default="REDACT", description="'REDACT' (reversible tokenization) or 'BLOCK' (fail-closed)")
    enabled: bool = Field(default=True, description="Whether the rule is actively evaluated")
    hit_count: int = Field(default=0, description="Cumulative times this rule matched outbound prompts")
    description: Optional[str] = Field(default="", description="Optional context or internal classification")
    created_at: float = Field(default_factory=time.time)


class CustomDictionaryManager:
    """Manages custom entity rules and executes deterministic matching across prompts."""

    def __init__(self, storage_path: Optional[Path] = None):
        self.storage_path = storage_path or (settings.DATA_DIR / "custom_entities.json")
        self._rules: Dict[str, CustomEntityRule] = {}
        self._compiled_cache: Dict[str, re.Pattern] = {}
        self._load()

    def _load(self):
        """Loads custom rules from JSON storage on disk."""
        if not self.storage_path.exists():
            # Seed default enterprise examples
            self._seed_defaults()
            return

        try:
            with open(self.storage_path, "r", encoding="utf-8") as f:
                raw_list = json.load(f)
            self._rules = {item["id"]: CustomEntityRule(**item) for item in raw_list}
            self._rebuild_cache()
        except Exception as e:
            logger.warning(f"Error loading custom entities: {e}. Starting fresh.")
            self._rules = {}

    def _save(self):
        """Persists custom rules atomically to disk."""
        try:
            self.storage_path.parent.mkdir(parents=True, exist_ok=True)
            data = [rule.model_dump() for rule in self._rules.values()]
            temp_path = self.storage_path.with_suffix(".tmp")
            with open(temp_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            temp_path.replace(self.storage_path)
            self._rebuild_cache()
        except Exception as e:
            logger.error(f"Failed to persist custom entities: {e}")

    def _seed_defaults(self):
        """Seeds initial template entities if none exist."""
        defaults = [
            CustomEntityRule(
                id="default_proj",
                name="Project Apollo (Example)",
                pattern="Project Apollo",
                is_regex=False,
                case_sensitive=False,
                placeholder_prefix="PROJECT",
                action="REDACT",
                enabled=False,
                description="Template codename rule for unreleased initiative"
            ),
            CustomEntityRule(
                id="default_client",
                name="Acme Health (Example)",
                pattern="Acme Health|Acme Corp",
                is_regex=True,
                case_sensitive=False,
                placeholder_prefix="CLIENT",
                action="REDACT",
                enabled=False,
                description="Template client privacy protection rule"
            )
        ]
        self._rules = {d.id: d for d in defaults}
        self._save()

    def _rebuild_cache(self):
        """Pre-compiles regex patterns for active rules."""
        self._compiled_cache.clear()
        for rule in self._rules.values():
            if not rule.enabled:
                continue
            flags = 0 if rule.case_sensitive else re.IGNORECASE
            try:
                if rule.is_regex:
                    pattern_str = f"({rule.pattern})"
                else:
                    # Escape literal string and enforce word boundary where possible
                    escaped = re.escape(rule.pattern.strip())
                    pattern_str = rf"\b({escaped})\b"
                
                compiled = re.compile(pattern_str, flags)
                self._compiled_cache[rule.id] = compiled
            except re.error as err:
                logger.warning(f"Invalid regex for rule {rule.id} ('{rule.pattern}'): {err}")

    def list_rules(self) -> List[CustomEntityRule]:
        """Returns all configured rules ordered by creation time."""
        return sorted(list(self._rules.values()), key=lambda r: r.created_at)

    def get_rule(self, rule_id: str) -> Optional[CustomEntityRule]:
        return self._rules.get(rule_id)

    def add_rule(self, rule: CustomEntityRule) -> CustomEntityRule:
        """Adds or updates a custom entity rule."""
        self._rules[rule.id] = rule
        self._save()
        return rule

    def delete_rule(self, rule_id: str) -> bool:
        """Removes a custom entity rule."""
        if rule_id in self._rules:
            del self._rules[rule_id]
            self._save()
            return True
        return False

    def toggle_rule(self, rule_id: str) -> Optional[CustomEntityRule]:
        """Toggles the enabled/disabled state of a rule."""
        rule = self._rules.get(rule_id)
        if rule:
            rule.enabled = not rule.enabled
            self._save()
            return rule
        return None

    def scan(self, text: str) -> List[DetectedSpan]:
        """Scans text against all active custom entity rules.
        
        Returns DetectedSpans with appropriate categories:
        - If action == 'BLOCK' -> EntityCategory.SECRET
        - If action == 'REDACT' -> EntityCategory.PII
        """
        if not text or not self._compiled_cache:
            return []

        spans: List[DetectedSpan] = []
        dirty_hit_counts = False

        for rule_id, regex in self._compiled_cache.items():
            rule = self._rules.get(rule_id)
            if not rule:
                continue

            for match in regex.finditer(text):
                start, end = match.span()
                matched_text = text[start:end]
                
                # Rule category according to action
                category = EntityCategory.SECRET if rule.action.upper() == "BLOCK" else EntityCategory.PII
                prefix = (rule.placeholder_prefix or "CONFIDENTIAL").upper().strip()

                span = DetectedSpan(
                    entity_type=EntityType.CUSTOM_ENTITY,
                    category=category,
                    start=start,
                    end=end,
                    matched_text=matched_text,
                    confidence=1.0,
                    metadata={
                        "custom_rule_id": rule.id,
                        "custom_name": rule.name,
                        "placeholder_prefix": prefix,
                        "action": rule.action.upper()
                    }
                )
                spans.append(span)

                rule.hit_count += 1
                dirty_hit_counts = True

        if dirty_hit_counts:
            # Save asynchronously or schedule batch save
            try:
                self._save()
            except Exception:
                pass

        return spans


# Global singleton instance
custom_dictionary_manager = CustomDictionaryManager()
