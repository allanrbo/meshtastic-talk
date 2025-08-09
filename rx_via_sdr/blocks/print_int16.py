import numpy as np
from gnuradio import gr
import pmt

class blk(gr.sync_block):
    def __init__(self, prefix=""):
        gr.sync_block.__init__(
            self,
            name='print_int16',
            in_sig=[np.int16],
            out_sig=[]
        )
        self.prefix = prefix


    def work(self, input_items, output_items):
        # print tags on input port (relative symbol indices)
        start = self.nitems_read(0)
        end = start + len(input_items[0])
        for t in self.get_tags_in_window(0, start, end):
            rel = t.offset - start
            key = pmt.to_python(t.key)
            val = pmt.to_python(t.value)
            self.logger.info(f"{self.prefix}: tag at {rel}: {key} = {val}")

        self.logger.info(f"{self.prefix}: {input_items[0]}")

        return len(input_items[0])
