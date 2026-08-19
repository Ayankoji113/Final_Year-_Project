"""Layer 3 - dense autoencoder, implemented in NumPy.

Why not PyTorch: the previous requirements.txt pulled in torch (~2 GB) and then
never imported it - the model was already NumPy. For a 43-dimensional input and
a 3-layer encoder/decoder, NumPy is faster to load, has no CUDA/DLL surface, and
keeps the gateway image small. This is still a deep autoencoder trained by
mini-batch backpropagation; nothing about the method is compromised.

Trained on NORMAL traffic only. Reconstruction error is the anomaly score: the
network never learns to rebuild attack traffic, so attacks reconstruct badly.
That is what gives the layer its zero-day property - it needs no attack labels.
"""
import numpy as np


class NumpyAutoencoder:
    """43 -> 32 -> 12 -> 32 -> 43 dense autoencoder with Adam and early stopping."""

    def __init__(self, input_dim, hidden=32, bottleneck=12, lr=1e-3,
                 epochs=300, batch=256, patience=15, seed=42, noise=0.0):
        """
        noise : std-dev of Gaussian corruption added to inputs during training
                (DENOISING autoencoder). This is not cosmetic.

                A plain autoencoder trained on normal-only traffic memorises the
                exact values it saw. Several features are near-constant in any
                synthetic corpus - body_upper_ratio had mean 0.0004 and sd
                0.0033 here - so a real request that merely capitalises a name
                lands many sigma out, reconstructs badly, and is blocked. That
                mechanism produced a 38% false-positive rate on legitimate
                traffic while the held-out test FPR still read 1.3%, because the
                test split shared the training corpus's quirks.

                Corrupting the input forces the network to learn the shape of
                the normal manifold rather than its exact coordinates, so small
                benign deviations no longer explode the reconstruction error.
                Attacks, which are far off-manifold, still do.
        """
        self.input_dim = input_dim
        self.lr, self.epochs, self.batch, self.patience = lr, epochs, batch, patience
        self.noise = noise
        rng = np.random.RandomState(seed)

        def xavier(a, b):
            return rng.randn(a, b).astype(np.float64) * np.sqrt(2.0 / (a + b))

        self.W = [xavier(input_dim, hidden), xavier(hidden, bottleneck),
                  xavier(bottleneck, hidden), xavier(hidden, input_dim)]
        self.b = [np.zeros(hidden), np.zeros(bottleneck),
                  np.zeros(hidden), np.zeros(input_dim)]
        self._m = [np.zeros_like(w) for w in self.W] + [np.zeros_like(x) for x in self.b]
        self._v = [np.zeros_like(w) for w in self.W] + [np.zeros_like(x) for x in self.b]
        self._t = 0
        self.history = []

    @staticmethod
    def _act(x):
        return np.maximum(0.0, x)

    @staticmethod
    def _dact(x):
        return (x > 0).astype(np.float64)

    def _forward(self, X):
        z1 = X @ self.W[0] + self.b[0]; a1 = self._act(z1)
        z2 = a1 @ self.W[1] + self.b[1]; a2 = self._act(z2)
        z3 = a2 @ self.W[2] + self.b[2]; a3 = self._act(z3)
        out = a3 @ self.W[3] + self.b[3]           # linear output
        return out, (X, z1, a1, z2, a2, z3, a3)

    def _adam(self, grads):
        """Adam keeps this stable at 43 features without hand-tuned LR decay."""
        self._t += 1
        b1, b2, eps = 0.9, 0.999, 1e-8
        params = self.W + self.b
        for i, (p, g) in enumerate(zip(params, grads)):
            self._m[i] = b1 * self._m[i] + (1 - b1) * g
            self._v[i] = b2 * self._v[i] + (1 - b2) * (g * g)
            mhat = self._m[i] / (1 - b1 ** self._t)
            vhat = self._v[i] / (1 - b2 ** self._t)
            p -= self.lr * mhat / (np.sqrt(vhat) + eps)

    def fit(self, X, X_val=None, verbose=True):
        X = np.asarray(X, dtype=np.float64)
        if X_val is None:                       # hold out 10% for early stopping
            n_val = max(1, int(0.1 * len(X)))
            rng = np.random.RandomState(0)
            idx = rng.permutation(len(X))
            X_val, X = X[idx[:n_val]], X[idx[n_val:]]
        X_val = np.asarray(X_val, dtype=np.float64)

        n = len(X)
        best, best_snapshot, wait = np.inf, None, 0
        rng = np.random.RandomState(1)

        for ep in range(self.epochs):
            order = rng.permutation(n)
            for s in range(0, n, self.batch):
                xb = X[order[s:s + self.batch]]
                if len(xb) < 2:
                    continue
                # Denoising: corrupt the input, but score the reconstruction
                # against the CLEAN target.
                xin = xb + rng.normal(0.0, self.noise, xb.shape) if self.noise else xb
                out, (x0, z1, a1, z2, a2, z3, a3) = self._forward(xin)
                d = 2.0 * (out - xb) / len(xb)

                gW4 = a3.T @ d;  gb4 = d.sum(0)
                d3 = (d @ self.W[3].T) * self._dact(z3)
                gW3 = a2.T @ d3; gb3 = d3.sum(0)
                d2 = (d3 @ self.W[2].T) * self._dact(z2)
                gW2 = a1.T @ d2; gb2 = d2.sum(0)
                d1 = (d2 @ self.W[1].T) * self._dact(z1)
                gW1 = x0.T @ d1; gb1 = d1.sum(0)

                self._adam([gW1, gW2, gW3, gW4, gb1, gb2, gb3, gb4])

            val = float(self.score(X_val).mean())
            self.history.append(val)
            if verbose and (ep + 1) % 25 == 0:
                print(f"      epoch {ep + 1:3d}/{self.epochs}  val_recon_mse={val:.6f}")

            if val < best - 1e-7:
                best, wait = val, 0
                best_snapshot = ([w.copy() for w in self.W], [x.copy() for x in self.b])
            else:
                wait += 1
                if wait >= self.patience:
                    if verbose:
                        print(f"      early stop at epoch {ep + 1} (best val={best:.6f})")
                    break

        if best_snapshot:                        # restore the best weights, not the last
            self.W, self.b = best_snapshot
        self.best_val = best
        return self

    def score(self, X):
        """Per-row mean squared reconstruction error = anomaly score."""
        X = np.asarray(X, dtype=np.float64)
        out, _ = self._forward(X)
        return ((X - out) ** 2).mean(axis=1)

    # Keep pickles small and version-tolerant: optimiser state is not needed
    # for inference and would otherwise triple the file size.
    def __getstate__(self):
        s = self.__dict__.copy()
        for k in ("_m", "_v"):
            s.pop(k, None)
        return s

    def __setstate__(self, state):
        self.__dict__.update(state)
        self._m = [np.zeros_like(w) for w in self.W] + [np.zeros_like(x) for x in self.b]
        self._v = [np.zeros_like(w) for w in self.W] + [np.zeros_like(x) for x in self.b]
