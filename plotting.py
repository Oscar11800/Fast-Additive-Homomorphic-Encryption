import matplotlib
import matplotlib.pyplot as plt


def plot_performance(data_points, title, x_label, y_label):
    keys = list(data_points.keys())
    values = list(data_points.values())

    plt.figure(figsize=(10, 6))
    plt.title(title)
    plt.xlabel(x_label)
    plt.ylabel(y_label)
    plt.plot(keys, values, linestyle="-", color="b")
    # for x, y in zip(keys, values):
    #     plt.text(x, y, f"({x}, {y:.3f})", color="red", fontsize=6)

    plt.grid(True)
    plt.savefig(f"graphs/{title.lower().replace(' ', '_')}.png")

def plot_ciphertext_size(data_points, title, x_label, y_label):
    keys = list(data_points.keys())
    values = list(data_points.values())

    plt.figure(figsize=(10, 6))
    plt.title(title)
    plt.xlabel(x_label)
    plt.ylabel(y_label)
    plt.plot(keys, values, linestyle="-", color="b")
    # for x, y in zip(keys, values):
    #     plt.text(x, y, f"({x}, {y:.3f})", color="red", fontsize=6)

    plt.grid(True)
    plt.savefig(f"graphs/{title.lower().replace(' ', '_')}.png")
    