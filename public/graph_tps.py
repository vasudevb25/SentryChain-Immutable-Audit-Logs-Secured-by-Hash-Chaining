import pandas as pd
import matplotlib.pyplot as plt

# ============================================
# Load CSV
# ============================================

df = pd.read_csv("block_metrics.csv")

# ============================================
# Convert timestamps
# ============================================

df["timestamp"] = pd.to_datetime(df["timestamp"])

# ============================================
# Plot
# ============================================

plt.figure(figsize=(10, 5))

plt.plot(
    df["timestamp"],
    df["block_index"],
    marker='o',
    linewidth=2
)

plt.xlabel("Time")

plt.ylabel("Block Count")

plt.title("Blockchain Growth Over Time")

plt.grid(True)

plt.xticks(rotation=20)

# Save graph
plt.savefig("block_timeline.png")

# Show graph
plt.show()