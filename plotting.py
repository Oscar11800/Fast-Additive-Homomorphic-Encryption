import matplotlib.pyplot as plt

def plot_security_param_vs_performance(security_params, time_performances, title, x_label, y_label):
    plt.figure=(10,6)
    plt.plot(security_params, time_performances, marker='o')
    plt.title(title)
    plt.xlabel(x_label)
    plt.ylabel(y_label)
    plt.grid=True
    plt.savefig(f"{title.lower().replace(' ', '_')}.png")
    plt.close

def plot_alpha_vs_performance(alphas, time_performances, title, x_label, y_label):
    plt.figure=(10,6)
    plt.plot(alphas, time_performances, marker='o')
    plt.title(title)
    plt.xlabel(x_label)
    plt.ylabel(y_label)
    plt.grid=True
    plt.savefig(f"{title.lower().replace(' ', '_')}.png")
    plt.close