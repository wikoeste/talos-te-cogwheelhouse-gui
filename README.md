# Web UI tool for Talos Escalations

# Requirements
Python\
Flask\
HTML\
API Keys

# Purpose
Streamline workflow from multiple web pages to one central UI (Example: TAC does this with CS1) management tool.

# Release Notes
0.0.2\
Consolidated navigation into one shared template across all active authenticated pages\
Standardized Tickets, Umbrella, Search, Scripts, Replay, and Staging dropdown content\
Updated generated ticket and results pages to retain the shared navigation\
Reduced the dashboard clock provider from six requests to one\
Added lazy image loading and asynchronous image decoding\
Added seven-day browser caching for static assets\
Improved responsive and keyboard-accessible navigation styling\
Introduced a modern dark visual system with layered surfaces, glass navigation, and consistent spacing\
Modernized forms, buttons, tables, result panels, dashboard tiles, and authentication states\
Added responsive result grids for metrics, Secure Endpoint, and Malware Analytics pages\
Added accessible focus states, reduced-motion support, mobile layouts, and page metadata\
Aligned the interface palette with Cisco Talos charcoal, blue, white, and orange\
Added a transparent knight watermark based on the supplied artwork\
Added the Greek Talos automaton watermark to the left side of every page\
Added an accessible minimize/expand control for the getacetix ticket list\
Added the Talos Escalations Team - COG Wheelhouse login title\
Corrected malformed HTML page structures and removed duplicated navigation markup

0.0.1\
Local install\
Beta release

None!\
This is a locally installed tool not running on any Talos hosts at this time.\
Ideally this would be similar to run like TE-Analysis, https://ava-tepot-01prd.vrt.sourcefire.com/\
