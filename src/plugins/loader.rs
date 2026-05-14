use super::recipe;

pub fn load_plugins_from_dirs(dirs: &[std::path::PathBuf]) -> Vec<recipe::Recipe> {
    let mut recipes = Vec::new();
    for dir in dirs {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().map(|e| e == "toml").unwrap_or(false) {
                    if let Ok(r) = recipe::parse_recipe_file(&path) {
                        recipes.push(r);
                    }
                }
            }
        }
    }
    recipes
}
