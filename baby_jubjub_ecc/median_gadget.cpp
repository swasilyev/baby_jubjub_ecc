//
// Created by svasilyev on 10/24/18.
//

#include "median_gadget.hpp"

namespace libsnark {
    template<typename FieldT, typename HashT>
    median_gadget<FieldT, HashT>::median_gadget(
            protoboard<FieldT> &pb,
            const size_t n,
            const std::vector<pb_variable_array<FieldT>> &pk_x_bins,
            const std::vector<pb_variable_array<FieldT>> &pk_y_bins,
            const std::vector<pb_variable_array<FieldT>> &r_x_bins,
            const std::vector<pb_variable_array<FieldT>> &r_y_bins,
            const std::vector<pb_variable_array<FieldT>> &ss,
            const std::vector<pb_variable_array<FieldT>> &ms) :
            gadget<FieldT>(pb, "median_gadget"),
            n(n),
            pk_x_bins(pk_x_bins),
            pk_y_bins(pk_y_bins),
            r_x_bins(r_x_bins),
            r_y_bins(r_y_bins),
            ss(ss),
            ms(ms)

    {
        assert(n > 0);
        assert(n % 2 == 1);
        assert(pk_x_bins.size() == n);
        assert(pk_y_bins.size() == n);
        assert(r_x_bins.size() == n);
        assert(r_y_bins.size() == n);
        assert(ss.size() == n);
        assert(ms.size() == n);

        median.allocate(pb, "median");
        a.allocate(pb, "a");
        d.allocate(pb, "d");
        base_x.allocate(pb, "base x");
        base_y.allocate(pb, "base y");

        for (size_t i = 0; i < n; i++) {
            signature_verifiers.emplace_back(eddsa<FieldT, HashT>(pb, a, d, pk_x_bins[i], pk_y_bins[i], base_x, base_y, r_x_bins[i], r_y_bins[i], ms[i], ss[i]));
        }

        less.allocate(pb, n, "less");
        less_or_eq.allocate(pb, n, "less_or_eq");

        for (size_t i = 0; i < n; i++) {
            packed_messages.emplace_back(pb_variable<FieldT>()); //TODO: could be better
            packed_messages[i].allocate(pb, "packed_messages_" + i);
            packers.emplace_back(packing_gadget<FieldT>(pb, ms[i], packed_messages[i], "packer_" + i));
            comparators.emplace_back(comparison_gadget<FieldT>(pb, FieldT::capacity(), median, packed_messages[i], less[i], less_or_eq[i], "comparator_" + i));
        }
    }

    template<typename FieldT, typename HashT>
    void median_gadget<FieldT, HashT>::generate_r1cs_constraints() {
        for (size_t i = 0; i < n; i++) {
            signature_verifiers[i].generate_r1cs_constraints();
            packers[i].generate_r1cs_constraints(false); //TODO: bitness
            comparators[i].generate_r1cs_constraints();
        }

        linear_combination<FieldT> less_or_eq_count = pb_sum<FieldT>(less_or_eq);
        linear_combination<FieldT> more_or_eq_count = n - pb_sum<FieldT>(less);
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, less_or_eq_count, more_or_eq_count), "less_or_eq_count == more_or_eq_count");
    }

    template<typename FieldT, typename HashT>
    void median_gadget<FieldT, HashT>::generate_r1cs_witness() {
        this->pb.val(a) = FieldT("168700");
        this->pb.val(d) = FieldT("168696");
        this->pb.val(base_x) = FieldT("17777552123799933955779906779655732241715742912184938656739573121738514868268");
        this->pb.val(base_y) = FieldT("2626589144620713026669568689430873010625803728049924121243784502389097019475");

        for (size_t i = 0; i < n; i++) {
            signature_verifiers[i].generate_r1cs_witness();
            packers[i].generate_r1cs_witness_from_bits();
        }

        this->pb.val(median) = this->pb.val(packed_messages[0]);

        for (size_t i = 0; i < n; i++) {
            comparators[i].generate_r1cs_witness();
            std::cout << "i = " << i
                      << ", m = " << this->pb.val(packed_messages[i])
                      << ", less = " << this->pb.val(less[i])
                      << ", less_or_eq = " << this->pb.val(less_or_eq[i])
                      << std::endl;
        }
    }
}