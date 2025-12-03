import hashlib



def update_dict_with_append(target_dict, *source_dicts):
    """
    Merge multiple source dictionaries into a target dictionary.
    
    Args:
        target_dict: Dictionary to be updated (modified in place)
        *source_dicts: Variable number of source dictionaries to merge into target
    """
    for source_dict in source_dicts:
        for key, value in source_dict.items():
            if key in target_dict:
                if isinstance(target_dict[key], list):
                    target_dict[key].extend(value)
            else:
                target_dict[key] = value
