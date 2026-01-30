"""
    Copyright 2025, Ford Motor Company
    Copyright 2022, Switch
"""

__version__ = "0.32.0"

import os
import sys

# Add HomePlugPWN to the project search path
current_file_path = os.path.abspath(__file__)
current_dir = os.path.dirname(current_file_path)
project_root = os.path.abspath(os.path.join(current_dir, '..'))
homeplugpwn_base_path = os.path.join(project_root, 'external_libs', 'HomePlugPWN')
if homeplugpwn_base_path not in sys.path:
    sys.path.insert(0, homeplugpwn_base_path)
