from typing import List
import tenseal as ts

class AdvancedStatistics:
    @staticmethod
    def homomorphic_sum(encrypted_values: List[ts.CKKSVector]):
        if not encrypted_values:
            raise ValueError("encrypted_values must be non-empty")
        acc = encrypted_values[0]
        for v in encrypted_values[1:]:
            acc = acc + v
        return acc

    @staticmethod
    def homomorphic_mean(encrypted_values: List[ts.CKKSVector]):
        if not encrypted_values:
            raise ValueError("encrypted_values must be non-empty")
        sum_val = AdvancedStatistics.homomorphic_sum(encrypted_values)
        return sum_val * (1.0 / float(len(encrypted_values)))

    @staticmethod
    def homomorphic_variance(encrypted_values: List[ts.CKKSVector]):
        if not encrypted_values:
            raise ValueError("encrypted_values must be non-empty")
        
        # Var(X) = E[X^2] - (E[X])^2
        # Note: This naive implementation increases depth significantly.
        # For production, one might compute sum(x^2) and sum(x) separately and combine on client,
        # or ensure sufficient poly_modulus_degree.
        
        n = float(len(encrypted_values))
        
        # Calculate sum of squares
        sum_sq = encrypted_values[0].square()
        for v in encrypted_values[1:]:
            sum_sq = sum_sq + v.square()
            
        # Calculate sum
        sum_val = AdvancedStatistics.homomorphic_sum(encrypted_values)
        
        # E[X^2] = sum_sq / n
        e_x2 = sum_sq * (1.0 / n)
        
        # (E[X])^2 = (sum_val / n)^2 = sum_val^2 / n^2
        e_x_sq = sum_val.square() * (1.0 / (n * n))
        
        variance = e_x2 - e_x_sq
        return variance

    @staticmethod
    def homomorphic_std_dev(encrypted_values: List[ts.CKKSVector]):
        # Standard deviation requires square root, which is hard in HE.
        # Usually we return variance and let the client sqrt it.
        return AdvancedStatistics.homomorphic_variance(encrypted_values)
        
    @staticmethod
    def homomorphic_min_max(encrypted_values: List[ts.CKKSVector]):
        # Min/Max is non-trivial in CKKS (requires comparison function which is approximate).
        # Typically we rely on client-side decryption of individual values or interactive protocols.
        # For this demo, we will return a placeholder or error, 
        # OR we can implement a very rough approximation if needed.
        # Given the constraints, we will skip true homomorphic min/max and advise client-side handling
        # or return the encrypted list for the client to decrypt and find min/max (if allowed).
        raise NotImplementedError("Homomorphic Min/Max not supported in this scheme without interaction.")
