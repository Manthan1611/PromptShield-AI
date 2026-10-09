"""AttackScenario model. Field names are part of the fixed database contract.

Note: this table stores *labeled descriptions* of known prompt-injection
patterns for educational/testing purposes (used by the Simulator and Lab
pages to let a user pick a scenario). It does not contain runnable exploit
code and the mock AI provider never executes real attacks.
"""

from extensions import db


class AttackScenario(db.Model):
    __tablename__ = "attack_scenarios"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(80), nullable=False, index=True)
    difficulty = db.Column(db.String(20), nullable=False)  # easy / medium / hard
    risk_level = db.Column(db.String(20), nullable=False)  # low / medium / high / critical
    expected_behavior = db.Column(db.Text, nullable=True)
    defense_strategy = db.Column(db.Text, nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "category": self.category,
            "difficulty": self.difficulty,
            "risk_level": self.risk_level,
            "expected_behavior": self.expected_behavior,
            "defense_strategy": self.defense_strategy,
        }

    def __repr__(self):
        return f"<AttackScenario {self.name}>"
