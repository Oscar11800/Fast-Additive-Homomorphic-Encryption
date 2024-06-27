import matplotlib
import matplotlib.pyplot as plt


def plot_security_param_vs_performance(data_points, title, x_label, y_label):
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
    plt.savefig(f"{title.lower().replace(' ', '_')}.png")

def plot_security_param_vs_ciphertext_length(data_points, title, x_label, y_label):
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
    plt.savefig(f"{title.lower().replace(' ', '_')}.png")
    


def plot_alpha_vs_performance(alphas, time_performances, title, x_label, y_label):
    plt.figure = (10, 6)
    plt.plot(alphas, time_performances, marker="o")
    plt.title(title)
    plt.xlabel(x_label)
    plt.ylabel(y_label)
    plt.grid = True
    plt.savefig(f"{title.lower().replace(' ', '_')}.png")
    plt.close
