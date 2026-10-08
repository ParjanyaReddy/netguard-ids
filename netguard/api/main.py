import os
import time
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, Query, HTTPException
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from netguard.alerts.store import AlertStore
from netguard.config import NetGuardConfig


def create_app(store: Optional[AlertStore] = None, dashboard_path: Optional[str] = None) -> FastAPI:
    config = NetGuardConfig()
    alert_store = store or AlertStore(config.db_path)

    app = FastAPI(
        title="NetGuard IDS API",
        description="REST API for NetGuard Network Traffic Analyzer & Mini Intrusion Detection System",
        version="1.0.0"
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    default_dashboard = dashboard_path or os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "dashboard", "index.html"
    )

    @app.get("/", response_class=HTMLResponse)
    def serve_dashboard():
        if os.path.exists(default_dashboard):
            return FileResponse(default_dashboard, media_type="text/html")
        return HTMLResponse("<h2>NetGuard IDS API is running. Dashboard not found.</h2>")

    @app.get("/health")
    def health_check():
        return {
            "status": "healthy",
            "service": "netguard-ids",
            "timestamp": time.time(),
            "database": "connected"
        }

    @app.get("/alerts")
    def get_alerts(
        type: Optional[str] = Query(None, description="Filter by alert type (port_scan, syn_flood, dns_tunnel, arp_spoof)"),
        severity: Optional[str] = Query(None, description="Filter by severity (low, medium, high, critical)"),
        since: Optional[float] = Query(None, description="Epoch timestamp threshold"),
        limit: int = Query(100, ge=1, le=1000, description="Max alerts to retrieve")
    ) -> List[Dict[str, Any]]:
        return alert_store.get_alerts(alert_type=type, severity=severity, since=since, limit=limit)

    @app.get("/stats/top-talkers")
    def get_top_talkers(
        limit: int = Query(10, ge=1, le=100, description="Max hosts to return")
    ) -> List[Dict[str, Any]]:
        return alert_store.get_top_talkers(limit=limit)

    @app.get("/stats/protocols")
    def get_protocols() -> Dict[str, int]:
        return alert_store.get_protocol_distribution()

    @app.get("/stats/recent")
    def get_recent_stats(
        limit: int = Query(60, ge=1, le=1440, description="Minutes of historical data")
    ) -> List[Dict[str, Any]]:
        return alert_store.get_minute_stats(limit=limit)

    @app.get("/stats/summary")
    def get_summary() -> Dict[str, Any]:
        alert_stats = alert_store.get_alerts_summary()
        top_talkers = alert_store.get_top_talkers(limit=5)
        protocols = alert_store.get_protocol_distribution()
        total_bytes = sum(t.get("bytes", 0) for t in top_talkers)

        return {
            "total_alerts": alert_stats["total_alerts"],
            "severities": alert_stats["severities"],
            "threats_by_type": alert_stats["threats_by_type"],
            "total_bytes_tracked": total_bytes,
            "active_protocols_count": len(protocols),
            "top_talkers_count": len(top_talkers)
        }

    return app


# Default application instance for Uvicorn
app = create_app()
