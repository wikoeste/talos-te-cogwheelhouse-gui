import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class LayoutIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.layout = (PROJECT_ROOT / "templates" / "layout.html").read_text(encoding="utf-8")
        cls.navigation = (PROJECT_ROOT / "templates" / "partials" / "navigation.html").read_text(encoding="utf-8")
        cls.styles = (PROJECT_ROOT / "static" / "css" / "main.css").read_text(encoding="utf-8")

    def test_report_generator_tile_and_menu_shortcuts(self):
        self.assertIn("<strong>Reports</strong>", self.layout)
        self.assertIn("http://127.0.0.1:8810/", self.layout)
        for report_type in ("executive", "rca", "sitrep"):
            self.assertIn(
                f"http://127.0.0.1:8810/generator?report={report_type}",
                self.navigation,
            )

    def test_staging_docs_and_layout_color_styles(self):
        self.assertIn("https://analysis-api.vrt.sourcefire.com/docs#/", self.navigation)
        self.assertIn(".layout-hub .clocks > div *", self.styles)
        self.assertIn("color: #ffffff !important;", self.styles)
        self.assertIn(".replay-tile.layout-tile", self.styles)
        self.assertIn("--tile-accent", self.styles)


if __name__ == "__main__":
    unittest.main()
