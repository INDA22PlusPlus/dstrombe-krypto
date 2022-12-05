
fn trim_last_item_from_path_str(path: &str) -> &str {
    let mut path = path;
    while let Some(index) = path.rfind('/') {
        path = &path[..index];
        if !path.ends_with('/') {
            return path;
        }
    }
    path
}
