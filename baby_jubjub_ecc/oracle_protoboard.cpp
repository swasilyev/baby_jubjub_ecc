//
// Created by swasilyev on 10/31/18.
//

namespace libsnark {

    template<typename FieldT, typename HashT>
    oracle_protoboard<FieldT, HashT>::oracle_protoboard(const size_t n):     
            n(n),
            pk_x_bins(n),
            pk_y_bins(n),
            r_x_bins(n),
            r_y_bins(n),
            ss(n),
            ms(n)
             {
        median.allocate(*this, "median");
        for (size_t i = 0; i < n; i++) {
            pk_x_bins[i].allocate(*this, 256, FMT("", "pk_x_bin_%zu", i)); //FMT("", "%zu", i)
            pk_y_bins[i].allocate(*this, 256, FMT("", "pk_y_bin_%zu", i));
            r_x_bins[i].allocate(*this, 256, FMT("", "r_x_bin_%zu", i));
            r_y_bins[i].allocate(*this, 256, FMT("", "r_y_bin_%zu", i));
            ss[i].allocate(*this, 256, FMT("", "s_%zu", i));
            ms[i].allocate(*this, 256, FMT("", "m_%zu", i));
        }
        _median_gadget.reset(new median_gadget<FieldT, HashT>(*this, n, median, pk_x_bins, pk_y_bins, r_x_bins, r_y_bins, ss, ms)); //TODO: annotation
        const size_t public_input_size = 1 + n * 2 * 256; // median + n public keys (points on the curve)
        this->set_input_sizes(public_input_size); // Which inputs are public is also important.
    }

    template<typename FieldT, typename HashT>
    void oracle_protoboard<FieldT, HashT>::generate_r1cs_constraints() {
        _median_gadget->generate_r1cs_constraints();
    }

    template<typename FieldT, typename HashT>
    void oracle_protoboard<FieldT, HashT>::generate_r1cs_witness() {
        _median_gadget->generate_r1cs_witness();
    }
}