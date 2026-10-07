"""
Backward compatibility shim.
Import from app.engine.heuristic_reviewer instead.
"""
from app.engine.heuristic_reviewer import HeuristicAmbiguityReviewer

# Backward compatibility alias
LLMAmbiguityReviewer = HeuristicAmbiguityReviewer
