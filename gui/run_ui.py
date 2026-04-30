import yaml
import logging
from logging_setup import setup_logging
from ui.main_window import MainWindow
from services.runner import Runner

if __name__ == "__main__":
    # load config
    with open("config.yaml", "r") as f:
        cfg = yaml.safe_load(f)

    setup_logging(cfg.get("logs_dir", "logs"))

    cfg["integration_mode"] = cfg.get("integration_mode", "mock")
    runner = Runner(cfg)

    bootstrap_logger = logging.getLogger("immunity.bootstrap")
    bootstrap_logger.propagate = False
    bootstrap_logger.info("Starting UI via run_ui.py", extra={"integration_mode": cfg["integration_mode"]})

    # Create and run GUI
    app = MainWindow(cfg, runner)
    app.run()
