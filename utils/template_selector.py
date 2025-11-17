# utils/template_selector.py

# Simple mapping: change returned IDs to match your templates from the UI.
# Make sure templates with these IDs exist in your templates table.
def pick_template(percentage):
    try:
        pct = float(percentage)
    except (TypeError, ValueError):
        return None

    # Example mapping:
    # < 60  -> template id 1
    # 60-69 -> template id 2
    # 70-79 -> template id 3
    # 80+   -> template id 4
    # Adjust values below to match the actual template IDs you created.
    if pct < 60:
        return 1
    elif pct < 70:
        return 2
    elif pct < 80:
        return 3
    else:
        return 4
