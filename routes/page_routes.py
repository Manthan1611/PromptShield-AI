"""
HTML page routes. All pages extend templates/base.html so the whole
site shares one navbar/design system, per the project contract.
"""

from flask import Blueprint, render_template

page_bp = Blueprint("page", __name__)


@page_bp.route("/")
def index():
    return render_template("index.html", active_page="home")


@page_bp.route("/dashboard")
def dashboard():
    return render_template("dashboard.html", active_page="dashboard")


@page_bp.route("/lab")
def lab():
    return render_template("lab.html", active_page="lab")


@page_bp.route("/simulator")
def simulator():
    return render_template("simulator.html", active_page="simulator")


@page_bp.route("/analytics")
def analytics():
    return render_template("analytics.html", active_page="analytics")


@page_bp.route("/research")
def research():
    return render_template("research.html", active_page="research")


@page_bp.route("/history")
def history():
    return render_template("history.html", active_page="history")


@page_bp.route("/evaluation")
def evaluation():
    return render_template("evaluation.html", active_page="evaluation")


@page_bp.route("/reports")
def reports():
    return render_template("reports.html", active_page="reports")


@page_bp.route("/arena")
def arena():
    return render_template("arena.html", active_page="arena")


@page_bp.route("/settings")
def settings():
    return render_template("settings.html", active_page="settings")


@page_bp.route("/admin")
def admin():
    return render_template("admin.html", active_page="admin")
