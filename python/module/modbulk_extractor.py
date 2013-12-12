import sys
from ctypes import *

#                      return type, flag,  arg,    feature_recorder_name, forensic path, feature,  feature_len, context,  context_len
BeCallback = CFUNCTYPE(c_int,       c_int, c_uint, c_char_p,              c_char_p,      c_char_p, c_size_t,    c_char_p, c_size_t   )

lib_be = cdll.LoadLibrary("./libbulk_extractor.so")
lib_be.bulk_extractor_open.restype = c_void_p
lib_be.bulk_extractor_open.argtypes = [BeCallback]
lib_be.bulk_extractor_analyze_buf.argtypes = [c_void_p, POINTER(c_ubyte), c_size_t]

def bulk_extractor_open(cb):
    cb = BeCallback(cb)
    return lib_be.bulk_extractor_open(cb);
def bulk_extractor_analyze_buf(handle, buf):
    if type(buf) == str:
        buf = bytearray(buf, 'utf-8')
    buf = (c_ubyte * len(buf)).from_buffer(buf)
    return lib_be.bulk_extractor_analyze_buf(handle, buf, len(buf))
def bulk_extractor_close(handle):
    return lib_be.bulk_extractor_close(handle)

FLAG_FEATURE = 0x0001
FLAG_HISTOGRAM = 0x0002
FLAG_CARVE = 0x0004

def _noop_cb(*args): return 0
class BulkExtractor():
    def __init__(self, cb):
        self.handle = bulk_extractor_open(cb)
    # BE object as a context (with BulkExtractor() as b_e:)
    def __enter__(self):
        return self
    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
        return False
    @staticmethod
    def wrap_callback(feature_cb=_noop_cb, histogram_cb=_noop_cb, carve_cb=_noop_cb):
        def callback(flag, arg, recorder_name, pos, feature, feature_len, context, context_len):
            if flag & FLAG_FEATURE:
                return feature_cb(recorder_name, pos, feature, context)
            elif flag & FLAG_HISTOGRAM:
                return histogram_cb(recorder_name, pos, feature, arg)
            elif flag & FLAG_CARVE:
                return carve_cb(recorder_name, pos, context, feature)
            return -1
        return callback
    def close(self):
        if self.handle is not None:
            bulk_extractor_close(self.handle)
            self.handle = None
    #
    # analysis methods
    #
    def analyze_buf(self, buf):
        return bulk_extractor_analyze_buf(self.handle, buf)

def main():
    def raw_callback(flag, arg, recorder_name, pos, feature, feature_len, context, context_len):
        args = locals()
        for argname in args:
            print(str(argname), ":", str(args[argname]), end=" ")
        print()
        return 0;

    def feature_callback(recorder_name, pos, feature, context):
        print("got a feature from", recorder_name, "(", feature, ")", "(", context, ")")
        return 0;
    def histogram_callback(recorder_name, pos, feature, count):
        print("got histogram data from", recorder_name, ":", feature, "x", count)
        return 0;
    def carve_callback(recorder_name, pos, carved_filename, carved_data):
        print("got carved data from", recorder_name, "with filename", carved_filename, "and length", len(carved_data))
        return 0;

    with BulkExtractor(raw_callback) as b_e:
        b_e.analyze_buf("ABCDEFG  demo@api.com Just a demo 617-555-1212 ok!")

    cb = BulkExtractor.wrap_callback(feature_cb=feature_callback,
            histogram_cb=histogram_callback, carve_cb=carve_callback)

    with BulkExtractor(cb) as b_e:
        b_e.analyze_buf("ABCDEFG  demo@api.com Just a demo 617-555-1212 ok!")

if __name__ == "__main__":
    main()
