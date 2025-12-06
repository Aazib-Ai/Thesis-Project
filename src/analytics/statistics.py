from typing import List


def homomorphic_mean(encrypted_values: List):
    if not encrypted_values:
        raise ValueError("encrypted_values must be non-empty")
    acc = encrypted_values[0]
    for v in encrypted_values[1:]:
        acc = acc + v
    acc = acc * (1.0 / float(len(encrypted_values)))
    try:
        acc.rescale_next()
    except Exception:
        pass
    return acc


def homomorphic_variance(encrypted_values: List):
    if not encrypted_values:
        raise ValueError("encrypted_values must be non-empty")
    mean_enc = homomorphic_mean(encrypted_values)
    squared = []
    for x in encrypted_values:
        s = x * x
        try:
            s.rescale_next()
        except Exception:
            pass
        squared.append(s)
    mean_sq = homomorphic_mean(squared)
    var_enc = mean_sq - (mean_enc * mean_enc)
    try:
        var_enc.rescale_next()
    except Exception:
        pass
    return var_enc
