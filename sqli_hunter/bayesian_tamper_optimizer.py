# -*- coding: utf-8 -*-
"""
Bayesian Optimizer for finding effective WAF tamper chains.

This module uses scikit-optimize to find the most effective combination
of tamper scripts to bypass WAFs for a given injection point. It is designed
to replace the simpler multi-armed bandit approach in tamper.py.
"""
import skopt
from typing import Callable, List, Tuple, Dict, Any

# The list of all available tamper scripts.
TAMPER_CATEGORIES = [
    'none', 'space2comment', 'randomcase', 'urlencode',
    'chardoubleencode', 'equaltolike', 'space2randomblank',
    'versionedkeywords', 'keywordsubstitution', 'hexencodekeywords',
    'addnullbyte', 'splitkeywords', 'functionsynonyms',
    'commentaroundkeywords',
]

class BayesianTamperOptimizer:
    """
    Uses Bayesian Optimization to find the most effective tamper chain.
    """
    def __init__(self,
                 objective_func: Callable[[Tuple[str, ...]], float],
                 max_chain_length: int = 3,
                 n_initial_points: int = 10,
                 n_calls: int = 30):
        """
        Args:
            objective_func: A function that takes a tamper chain (tuple of strings)
                            and returns a score to be minimized.
            max_chain_length: The maximum number of tampers to chain together.
            n_initial_points: The number of random points to sample before fitting the model.
            n_calls: The total number of evaluations (tamper chains to try).
        """
        if n_initial_points >= n_calls:
            raise ValueError("n_calls must be greater than n_initial_points.")

        self.objective_func = objective_func
        self.max_chain_length = max_chain_length
        self.n_initial_points = n_initial_points
        self.n_calls = n_calls

        # Define the search space. It's a sequence of categorical variables.
        # Each variable represents a slot in the tamper chain.
        self.space = [
            skopt.space.Categorical(TAMPER_CATEGORIES, name=f"tamper_{i}")
            for i in range(self.max_chain_length)
        ]

    def _objective_wrapper(self, params: List[str]) -> float:
        """
        A wrapper to convert the list of parameters from skopt
        into a clean tuple of tampers for the real objective function.
        It filters out 'none' values.
        """
        tamper_chain = tuple(p for p in params if p != 'none')

        # Call the actual objective function provided by the Scanner
        return self.objective_func(tamper_chain)

    def optimize(self) -> Tuple[Tuple[str, ...], float]:
        """
        Runs the Bayesian optimization process to find the best tamper chain.

        Returns:
            A tuple containing:
            - The best tamper chain found (tuple of strings).
            - The score of the best chain.
        """
        print(f"[*] Starting Bayesian Optimization for tamper chain ({self.n_calls} calls)...")

        result = skopt.gp_minimize(
            func=self._objective_wrapper,
            dimensions=self.space,
            n_calls=self.n_calls,
            n_initial_points=self.n_initial_points,
            random_state=None # Use a different random seed each time
        )

        best_chain_list = result.x
        best_score = result.fun

        # Clean up the best chain by removing 'none's
        best_chain_tuple = tuple(p for p in best_chain_list if p != 'none')

        print(f"[*] Bayesian Optimization finished. Best chain: {best_chain_tuple}, Score: {best_score:.4f}")

        return best_chain_tuple, best_score

if __name__ == '__main__':
    # Example usage for testing

    # A dummy objective function that simulates a WAF and a vulnerability.
    # It "likes" the chain ('space2comment', 'randomcase').
    def dummy_objective(chain: Tuple[str, ...]) -> float:
        print(f"  Testing chain: {chain}")
        # WAF penalty: high if certain tampers are used alone
        waf_penalty = 0
        if 'urlencode' in chain and len(chain) == 1:
            waf_penalty = 1.0 # Blocked

        # Detection signal: reward for the specific chain
        detection_signal = 0
        if chain == ('space2comment', 'randomcase'):
            detection_signal = 1.0 # Vulnerability found

        # Score = WAF Penalty - Detection Signal
        # We want to minimize this score.
        # Best score is -1.0 (no block, vuln found)
        # Worst score is 1.0 (blocked)
        score = waf_penalty - detection_signal
        print(f"    -> Score: {score:.2f} (WAF: {waf_penalty}, Signal: {detection_signal})")
        return score

    optimizer = BayesianTamperOptimizer(
        objective_func=dummy_objective,
        max_chain_length=3,
        n_initial_points=5,
        n_calls=15
    )

    best_chain, best_score = optimizer.optimize()

    print(f"\n--- OPTIMIZATION COMPLETE ---")
    print(f"Optimal Tamper Chain: {best_chain}")
    print(f"Optimal Score: {best_score}")
