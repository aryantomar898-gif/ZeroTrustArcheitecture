"""
S7: Scoring engine for the simulation platform.
Evaluates user response actions against the scenario timeline.
"""

from __future__ import annotations


class ScoringEngine:
    """Evaluates and scores incident response actions."""
    
    def __init__(self, scenario_duration: int = 60):
        self.score = 0
        self.max_score = 100
        self.penalties = 0
        self.scenario_duration = scenario_duration
        self.actions_taken = set()
        
    def evaluate_action(self, action_type: str, current_minute: int) -> dict:
        """Evaluate an action taken by the user."""
        points = 0
        message = ""
        
        if action_type == "block_smb":
            if "block_smb" not in self.actions_taken:
                points = 25
                if current_minute <= 15:
                    points += 10  # Speed bonus
                    message = "Excellent! Rapid containment of SMB propagation."
                else:
                    message = "SMB blocked. Good, but earlier would have prevented DC infection."
            self.actions_taken.add("block_smb")
            
        elif action_type == "microsegment":
            if "microsegment" not in self.actions_taken:
                points = 20
                if current_minute <= 20:
                    message = "Subnets isolated successfully before lateral movement."
                else:
                    message = "Subnets isolated. Ransomware spread contained."
            self.actions_taken.add("microsegment")
            
        elif action_type == "session_revoke":
            if "session_revoke" not in self.actions_taken:
                points = 15
                message = "Compromised user sessions revoked."
            self.actions_taken.add("session_revoke")
            
        elif action_type == "killswitch_3":
            if "killswitch_3" not in self.actions_taken:
                points = 30
                message = "Kill-switch level 3 activated. Full network containment."
            self.actions_taken.add("killswitch_3")
            
        elif action_type == "killswitch_5":
            # Level 5 is extreme. Might be unnecessary or cause business disruption.
            points = 10
            self.penalties += 10
            message = "Full isolation activated. Containment successful but significant business disruption incurred."
            self.actions_taken.add("killswitch_5")
            
        else:
            return {"points": 0, "message": f"Action '{action_type}' recorded."}
            
        self.score = min(self.max_score, self.score + points)
        return {"points": points, "message": message, "current_score": self.score}
        
    def get_final_score(self) -> dict:
        """Calculate final grade."""
        grade = "F"
        if self.score >= 90:
            grade = "A"
        elif self.score >= 80:
            grade = "B"
        elif self.score >= 70:
            grade = "C"
        elif self.score >= 60:
            grade = "D"
            
        return {
            "score": self.score,
            "max_score": self.max_score,
            "penalties": self.penalties,
            "grade": grade,
            "actions": list(self.actions_taken)
        }
