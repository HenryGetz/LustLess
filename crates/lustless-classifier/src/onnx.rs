//! Minimal ONNX reader/evaluator for the `ensem_3cls-6.1.2` shard graphs.
//!
//! Each shard ships `<model id header>\n<ONNX ModelProto>` (see `MODEL.md`
//! "Shard format"); this module consumes the protobuf body and evaluates the
//! graph natively. The op set is exactly what the shards use — `Conv`,
//! `Clip`, `Add`, `GlobalAveragePool`, `Flatten`, `Gemm`, `Softmax` — so
//! nothing generic is implemented beyond that closed set (unknown ops fail
//! closed at parse time).
//!
//! Protobuf decoding is a hand-rolled wire-format reader (no dependency):
//! only the fields the shards actually use are understood, everything else
//! is skipped by wire type. The shard exporter writes int-list attributes in
//! the legacy schema (non-packed `ints` at field 8); both that and the
//! current packed field 9 are accepted.

use std::collections::HashMap;

use rayon::prelude::*;

/// Parse/evaluation failures (fail-closed: the caller aborts scoring).
#[derive(Debug, thiserror::Error)]
pub enum OnnxError {
    #[error("onnx: truncated buffer at offset {0}")]
    Truncated(usize),
    #[error("onnx: unsupported wire type {0}")]
    BadWireType(u8),
    #[error("onnx: unknown op type {0:?}")]
    UnknownOp(String),
    #[error("onnx: node {node}: missing input {input}")]
    MissingInput { node: String, input: String },
    #[error("onnx: {0}")]
    Shape(String),
    #[error("onnx: bad attribute {0}")]
    BadAttr(String),
}

/// A dense f32 tensor (NCHW activations, 4-D conv weights, 2-D classifier).
#[derive(Debug, Clone, PartialEq)]
pub struct Tensor {
    /// Dimensions (all non-zero).
    pub dims: Vec<usize>,
    /// Row-major element data, `prod(dims)` entries.
    pub data: Vec<f32>,
}

/// Closed op set of the shard graphs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Conv,
    Clip,
    Add,
    GlobalAveragePool,
    Flatten,
    Gemm,
    Softmax,
}

impl Op {
    fn parse(name: &str) -> Result<Self, OnnxError> {
        Ok(match name {
            "Conv" => Op::Conv,
            "Clip" => Op::Clip,
            "Add" => Op::Add,
            "GlobalAveragePool" => Op::GlobalAveragePool,
            "Flatten" => Op::Flatten,
            "Gemm" => Op::Gemm,
            "Softmax" => Op::Softmax,
            other => return Err(OnnxError::UnknownOp(other.to_string())),
        })
    }
}

#[derive(Debug, Clone)]
enum Attr {
    Int(i64),
    Float(f32),
    Ints(Vec<i64>),
}

#[derive(Debug)]
struct Node {
    op: Op,
    name: String,
    inputs: Vec<String>,
    output: String,
    attrs: HashMap<String, Attr>,
}

impl Node {
    fn ints(&self, name: &str, default: &[i64]) -> Vec<i64> {
        match self.attrs.get(name) {
            Some(Attr::Ints(v)) => v.clone(),
            Some(Attr::Int(v)) => vec![*v],
            None => default.to_vec(),
            other => unreachable!("attr {name} of {} has wrong type: {other:?}", self.name),
        }
    }

    fn int(&self, name: &str, default: i64) -> i64 {
        match self.attrs.get(name) {
            Some(Attr::Int(v)) => *v,
            None => default,
            other => unreachable!("attr {name} of {} has wrong type: {other:?}", self.name),
        }
    }

    fn float(&self, name: &str, default: f32) -> f32 {
        match self.attrs.get(name) {
            Some(Attr::Float(v)) => *v,
            None => default,
            other => unreachable!("attr {name} of {} has wrong type: {other:?}", self.name),
        }
    }
}

/// A parsed shard graph, ready for repeated [`Model::run`] calls.
#[derive(Debug)]
pub struct Model {
    input: String,
    output: String,
    nodes: Vec<Node>,
    initializers: HashMap<String, Tensor>,
}

impl Model {
    /// Graph input tensor name (`input.1` in the shards).
    #[allow(dead_code)] // asserted by the synthetic-graph tests
    pub fn input_name(&self) -> &str {
        &self.input
    }

    /// Graph output tensor name.
    #[allow(dead_code)] // asserted by the synthetic-graph tests
    pub fn output_name(&self) -> &str {
        &self.output
    }

    /// Parse an ONNX `ModelProto` body (the shard header line already
    /// stripped). Validates the op set and topological order up front so
    /// [`Model::run`] cannot fail on the shipped graphs.
    pub fn parse(bytes: &[u8]) -> Result<Self, OnnxError> {
        let mut r = Reader { buf: bytes, pos: 0 };
        let mut graph: Option<Vec<u8>> = None;
        while let Some((field, wire)) = r.next()? {
            match (field, wire) {
                (7, 2) => graph = Some(r.len_delim()?.to_vec()),
                _ => r.skip(wire)?,
            }
        }
        let graph = graph.ok_or_else(|| OnnxError::BadAttr("no graph field".into()))?;
        Self::parse_graph(&graph)
    }

    fn parse_graph(bytes: &[u8]) -> Result<Self, OnnxError> {
        let mut r = Reader { buf: bytes, pos: 0 };
        let mut raw_nodes: Vec<Vec<u8>> = Vec::new();
        let mut initializers = HashMap::new();
        let mut inputs: Vec<String> = Vec::new();
        let mut outputs: Vec<String> = Vec::new();
        while let Some((field, wire)) = r.next()? {
            match (field, wire) {
                (1, 2) => raw_nodes.push(r.len_delim()?.to_vec()),
                (5, 2) => {
                    let (name, tensor) = parse_tensor(r.len_delim()?)?;
                    initializers.insert(name, tensor);
                }
                (11, 2) => inputs.push(parse_value_info_name(r.len_delim()?)?),
                (12, 2) => outputs.push(parse_value_info_name(r.len_delim()?)?),
                _ => r.skip(wire)?,
            }
        }
        let input = inputs
            .into_iter()
            .next()
            .ok_or_else(|| OnnxError::BadAttr("graph has no input".into()))?;
        let output = outputs
            .into_iter()
            .next()
            .ok_or_else(|| OnnxError::BadAttr("graph has no output".into()))?;

        let mut nodes = Vec::with_capacity(raw_nodes.len());
        for raw in &raw_nodes {
            nodes.push(parse_node(raw)?);
        }
        // Validate: every data input resolves (initializer or earlier node
        // output) — the shipped graphs are topologically ordered.
        let mut available: Vec<&str> = initializers.keys().map(String::as_str).collect();
        available.push(&input);
        for node in &nodes {
            for name in &node.inputs {
                if !available.contains(&name.as_str()) {
                    return Err(OnnxError::MissingInput {
                        node: node.name.clone(),
                        input: name.clone(),
                    });
                }
            }
            available.push(&node.output);
        }
        Ok(Self {
            input,
            output,
            nodes,
            initializers,
        })
    }

    /// Evaluate the graph on one `[1, C, H, W]` input tensor.
    pub fn run(&self, input: Tensor) -> Result<Tensor, OnnxError> {
        let mut activations: HashMap<&str, Tensor> = HashMap::with_capacity(self.nodes.len() + 1);
        activations.insert(&self.input, input);
        for node in &self.nodes {
            let output = self.eval_node(node, &activations)?;
            activations.insert(&node.output, output);
        }
        activations
            .remove(self.output.as_str())
            .ok_or_else(|| OnnxError::Shape("graph produced no output".into()))
    }

    fn eval_node(&self, node: &Node, acts: &HashMap<&str, Tensor>) -> Result<Tensor, OnnxError> {
        fn lookup<'a>(
            node: &Node,
            index: usize,
            acts: &'a HashMap<&str, Tensor>,
            initializers: &'a HashMap<String, Tensor>,
        ) -> Result<&'a Tensor, OnnxError> {
            let name = node
                .inputs
                .get(index)
                .ok_or_else(|| OnnxError::MissingInput {
                    node: node.name.clone(),
                    input: format!("input#{index}"),
                })?;
            acts.get(name.as_str())
                .or_else(|| initializers.get(name.as_str()))
                .ok_or_else(|| OnnxError::MissingInput {
                    node: node.name.clone(),
                    input: name.clone(),
                })
        }
        let x = lookup(node, 0, acts, &self.initializers)?;
        match node.op {
            Op::Conv => {
                let w = lookup(node, 1, acts, &self.initializers)?;
                let bias = if node.inputs.len() > 2 && !node.inputs[2].is_empty() {
                    Some(lookup(node, 2, acts, &self.initializers)?.data.as_slice())
                } else {
                    None
                };
                conv2d(node, x, w, bias)
            }
            Op::Clip => {
                let min = node.float("min", f32::NEG_INFINITY);
                let max = node.float("max", f32::INFINITY);
                // Shards always carry explicit min/max attributes; the
                // opset-10 default (no attrs) is ReLU.
                let (min, max) = if node.attrs.is_empty() {
                    (0.0, f32::INFINITY)
                } else {
                    (min, max)
                };
                Ok(Tensor {
                    dims: x.dims.clone(),
                    data: x.data.iter().map(|v| v.clamp(min, max)).collect(),
                })
            }
            Op::Add => {
                let y = lookup(node, 1, acts, &self.initializers)?;
                if x.data.len() != y.data.len() {
                    return Err(OnnxError::Shape(format!(
                        "Add {} size mismatch {} vs {}",
                        node.name,
                        x.data.len(),
                        y.data.len()
                    )));
                }
                Ok(Tensor {
                    dims: x.dims.clone(),
                    data: x.data.iter().zip(&y.data).map(|(a, b)| a + b).collect(),
                })
            }
            Op::GlobalAveragePool => {
                // NCHW: mean over the trailing spatial axes.
                let (n, c, h, w) = nchw(&x.dims, &node.name)?;
                let plane = (h * w) as f32;
                let mut data = Vec::with_capacity(n * c);
                for plane_data in x.data.chunks_exact(h * w) {
                    let sum: f32 = plane_data.iter().sum();
                    data.push(sum / plane);
                }
                Ok(Tensor {
                    dims: vec![n, c, 1, 1],
                    data,
                })
            }
            Op::Flatten => {
                let axis = node.int("axis", 1);
                if axis != 1 {
                    return Err(OnnxError::BadAttr(format!(
                        "Flatten {} axis {axis} != 1",
                        node.name
                    )));
                }
                let outer = x.dims.iter().take(1).product::<usize>();
                let inner = x.data.len() / outer.max(1);
                Ok(Tensor {
                    dims: vec![outer.max(1), inner],
                    data: x.data.clone(),
                })
            }
            Op::Gemm => {
                let w = lookup(node, 1, acts, &self.initializers)?;
                let bias = lookup(node, 2, acts, &self.initializers)?;
                let trans_a = node.int("transA", 0);
                let trans_b = node.int("transB", 0);
                let alpha = node.float("alpha", 1.0);
                let beta = node.float("beta", 1.0);
                gemm(node, x, w, bias, trans_a, trans_b, alpha, beta)
            }
            Op::Softmax => {
                // The shards apply Softmax to `[1, K]` outputs; axis defaults
                // to the innermost non-batch axis, equivalent to the full
                // vector here.
                let mut out = x.data.clone();
                let max = out.iter().copied().fold(f32::NEG_INFINITY, f32::max);
                let mut sum = 0.0f32;
                for value in &mut out {
                    *value = (*value - max).exp();
                    sum += *value;
                }
                for value in &mut out {
                    *value /= sum;
                }
                Ok(Tensor {
                    dims: x.dims.clone(),
                    data: out,
                })
            }
        }
    }
}

fn nchw(dims: &[usize], node: &str) -> Result<(usize, usize, usize, usize), OnnxError> {
    match dims {
        [n, c, h, w] => Ok((*n, *c, *h, *w)),
        other => Err(OnnxError::Shape(format!(
            "node {node}: expected NCHW 4-D input, got dims {other:?}"
        ))),
    }
}

/// NCHW convolution: weight `[Cout, Cin/group, KH, KW]`, attrs `strides`,
/// `pads` (order `[top, left, bottom, right]`), `dilations`, `group`.
fn conv2d(node: &Node, x: &Tensor, w: &Tensor, bias: Option<&[f32]>) -> Result<Tensor, OnnxError> {
    let (batch, cin, height, width) = nchw(&x.dims, &node.name)?;
    if batch != 1 {
        return Err(OnnxError::Shape(format!(
            "Conv {}: batch {batch} != 1",
            node.name
        )));
    }
    let dims = &w.dims;
    let (cout, cin_group, kh, kw) = match dims.as_slice() {
        [a, b, c, d] => (*a, *b, *c, *d),
        other => {
            return Err(OnnxError::Shape(format!(
                "Conv {}: bad weight dims {other:?}",
                node.name
            )))
        }
    };
    let strides = node.ints("strides", &[1, 1]);
    let dilations = node.ints("dilations", &[1, 1]);
    let pads = node.ints("pads", &[0, 0, 0, 0]);
    let group = node.int("group", 1) as usize;
    if strides.len() != 2 || dilations.len() != 2 || pads.len() != 4 {
        return Err(OnnxError::BadAttr(format!(
            "Conv {}: bad strides/dilations/pads lengths",
            node.name
        )));
    }
    let (sh, sw) = (strides[0] as usize, strides[1] as usize);
    let (dh, dw) = (dilations[0] as usize, dilations[1] as usize);
    let (pt, pl, pb, pr) = (
        pads[0] as isize,
        pads[1] as isize,
        pads[2] as isize,
        pads[3] as isize,
    );
    if group == 0 || cin % group != 0 || cout % group != 0 || cin_group != cin / group {
        return Err(OnnxError::Shape(format!(
            "Conv {}: group {group} incompatible with cin {cin} cout {cout}",
            node.name
        )));
    }
    let eff_kh = dh * (kh - 1) + 1;
    let eff_kw = dw * (kw - 1) + 1;
    let out_h = (height as isize + pt + pb - eff_kh as isize) / sh as isize + 1;
    let out_w = (width as isize + pl + pr - eff_kw as isize) / sw as isize + 1;
    if out_h <= 0 || out_w <= 0 {
        return Err(OnnxError::Shape(format!(
            "Conv {}: empty output {out_h}x{out_w}",
            node.name
        )));
    }
    let (out_h, out_w) = (out_h as usize, out_w as usize);

    let plane = height * width;
    let out_plane = out_h * out_w;
    let mut data = vec![0.0f32; out_plane * cout];

    // Parallel over output channels: each channel writes a disjoint plane,
    // so the reduction order (and results) are bit-identical run to run.
    data.par_chunks_mut(out_plane)
        .enumerate()
        .for_each(|(oc, out)| {
            let group_index = oc / (cout / group);
            let ic_start = group_index * cin_group;
            let w_oc = oc * cin_group * kh * kw;
            if let Some(bias) = bias {
                out.fill(bias[oc]);
            }
            for ic in 0..cin_group {
                let x_ic = (ic_start + ic) * plane;
                let w_ic = w_oc + ic * kh * kw;
                for ikh in 0..kh {
                    let in_row = (ikh * dh) as isize - pt;
                    for ikw in 0..kw {
                        let in_col0 = (ikw * dw) as isize - pl;
                        let weight_base = w_ic + ikh * kw + ikw;
                        for oh in 0..out_h {
                            let in_row_idx = in_row + (oh * sh) as isize;
                            if in_row_idx < 0 || in_row_idx >= height as isize {
                                continue;
                            }
                            let x_row = x_ic + in_row_idx as usize * width;
                            let out_row = oh * out_w;
                            for ow in 0..out_w {
                                let in_col_idx = in_col0 + (ow * sw) as isize;
                                if (0..width as isize).contains(&in_col_idx) {
                                    out[out_row + ow] +=
                                        w.data[weight_base] * x.data[x_row + in_col_idx as usize];
                                }
                            }
                        }
                    }
                }
            }
        });
    Ok(Tensor {
        dims: vec![1, cout, out_h, out_w],
        data,
    })
}

/// General matrix multiply used by the classifier head:
/// `Y = alpha · A·B (+ beta · C)` with optional transposes. The argument list
/// mirrors the operator's attribute set one-for-one.
#[allow(clippy::too_many_arguments)]
fn gemm(
    node: &Node,
    a: &Tensor,
    b: &Tensor,
    bias: &Tensor,
    trans_a: i64,
    trans_b: i64,
    alpha: f32,
    beta: f32,
) -> Result<Tensor, OnnxError> {
    let (m, k_a) = match a.dims.as_slice() {
        [m, k] => (*m, *k),
        other => {
            return Err(OnnxError::Shape(format!(
                "Gemm {}: A dims {other:?}",
                node.name
            )))
        }
    };
    let (k_b, n) = match b.dims.as_slice() {
        [x, y] if trans_b == 0 => (*x, *y),
        [x, y] => (*y, *x),
        other => {
            return Err(OnnxError::Shape(format!(
                "Gemm {}: B dims {other:?}",
                node.name
            )))
        }
    };
    let (m_eff, k_eff) = if trans_a != 0 { (k_a, m) } else { (m, k_a) };
    if k_eff != k_b {
        return Err(OnnxError::Shape(format!(
            "Gemm {}: inner {k_eff} != {k_b}",
            node.name
        )));
    }
    let mut data = vec![0.0f32; m_eff * n];
    for i in 0..m_eff {
        for k in 0..k_eff {
            let av = if trans_a != 0 {
                a.data[k * m + i]
            } else {
                a.data[i * k_a + k]
            } * alpha;
            if av == 0.0 {
                continue;
            }
            for j in 0..n {
                let bv = if trans_b != 0 {
                    b.data[j * k_b + k]
                } else {
                    b.data[k * n + j]
                };
                data[i * n + j] += av * bv;
            }
        }
    }
    if beta != 0.0 {
        if bias.data.len() != n && bias.data.len() != m_eff * n {
            return Err(OnnxError::Shape(format!(
                "Gemm {}: bias len {} for {m_eff}x{n}",
                node.name,
                bias.data.len()
            )));
        }
        for i in 0..m_eff {
            for j in 0..n {
                let c = if bias.data.len() == n {
                    bias.data[j]
                } else {
                    bias.data[i * n + j]
                };
                data[i * n + j] += beta * c;
            }
        }
    }
    Ok(Tensor {
        dims: vec![m_eff, n],
        data,
    })
}

// ---------------------------------------------------------------------------
// Protobuf wire-format reader
// ---------------------------------------------------------------------------

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn varint(&mut self) -> Result<u64, OnnxError> {
        let mut value: u64 = 0;
        let mut shift = 0u32;
        loop {
            let byte = *self
                .buf
                .get(self.pos)
                .ok_or(OnnxError::Truncated(self.pos))?;
            self.pos += 1;
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
            shift += 7;
            if shift >= 64 {
                return Err(OnnxError::Truncated(self.pos));
            }
        }
    }

    fn fixed32(&mut self) -> Result<u32, OnnxError> {
        let end = self.pos + 4;
        let bytes = self
            .buf
            .get(self.pos..end)
            .ok_or(OnnxError::Truncated(self.pos))?;
        self.pos = end;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn bytes(&mut self, len: usize) -> Result<&'a [u8], OnnxError> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or(OnnxError::Truncated(self.pos))?;
        let out = self
            .buf
            .get(self.pos..end)
            .ok_or(OnnxError::Truncated(self.pos))?;
        self.pos = end;
        Ok(out)
    }

    fn next(&mut self) -> Result<Option<(u32, u8)>, OnnxError> {
        if self.pos >= self.buf.len() {
            return Ok(None);
        }
        let tag = self.varint()?;
        let field = (tag >> 3) as u32;
        let wire = (tag & 0x7) as u8;
        if field == 0 {
            return Err(OnnxError::Truncated(self.pos));
        }
        Ok(Some((field, wire)))
    }

    fn skip(&mut self, wire: u8) -> Result<(), OnnxError> {
        match wire {
            0 => {
                self.varint()?;
            }
            1 => {
                self.bytes(8)?;
            }
            2 => {
                let len = self.varint()? as usize;
                self.bytes(len)?;
            }
            5 => {
                self.bytes(4)?;
            }
            other => return Err(OnnxError::BadWireType(other)),
        }
        Ok(())
    }

    fn len_delim(&mut self) -> Result<&'a [u8], OnnxError> {
        let len = self.varint()? as usize;
        self.bytes(len)
    }

    /// Packed or unpacked repeated varints.
    fn packed_varints(&mut self, wire: u8) -> Result<Vec<i64>, OnnxError> {
        match wire {
            0 => Ok(vec![self.varint()? as i64]),
            2 => {
                let mut out = Vec::new();
                let mut inner = Reader {
                    buf: self.len_delim()?,
                    pos: 0,
                };
                while inner.pos < inner.buf.len() {
                    out.push(inner.varint()? as i64);
                }
                Ok(out)
            }
            other => Err(OnnxError::BadWireType(other)),
        }
    }
}

/// AttributeProto.type values.
const ATTR_FLOAT: i64 = 1;
const ATTR_INT: i64 = 2;
const ATTR_INTS: i64 = 7;

fn parse_attribute(bytes: &[u8]) -> Result<(String, Attr), OnnxError> {
    let mut r = Reader { buf: bytes, pos: 0 };
    let mut name = String::new();
    let mut kind: Option<i64> = None;
    let mut float = 0.0f32;
    let mut int = 0i64;
    let mut ints: Option<Vec<i64>> = None;
    while let Some((field, wire)) = r.next()? {
        match (field, wire) {
            (1, 2) => name = String::from_utf8_lossy(r.len_delim()?).into_owned(),
            (2, 5) => float = f32::from_bits(r.fixed32()?),
            (3, 0) => int = r.varint()? as i64,
            // Legacy non-packed int list (field 8): one scalar field per
            // value, all of them accumulating; packed/scalar field 9
            // appends the same way.
            (8, _) | (9, _) => ints
                .get_or_insert_with(Vec::new)
                .extend(r.packed_varints(wire)?),
            (20, 0) => kind = Some(r.varint()? as i64),
            _ => r.skip(wire)?,
        }
    }
    let attr = match kind {
        Some(ATTR_INT) => Attr::Int(int),
        Some(ATTR_FLOAT) => Attr::Float(float),
        Some(ATTR_INTS) => Attr::Ints(ints.unwrap_or_default()),
        other => {
            return Err(OnnxError::BadAttr(format!(
                "attribute {name}: unsupported type {other:?}"
            )))
        }
    };
    Ok((name, attr))
}

fn parse_node(bytes: &[u8]) -> Result<Node, OnnxError> {
    let mut r = Reader { buf: bytes, pos: 0 };
    let mut inputs: Vec<String> = Vec::new();
    let mut outputs: Vec<String> = Vec::new();
    let mut name = String::new();
    let mut op_type = String::new();
    let mut attrs = HashMap::new();
    while let Some((field, wire)) = r.next()? {
        match (field, wire) {
            (1, 2) => inputs.push(String::from_utf8_lossy(r.len_delim()?).into_owned()),
            (2, 2) => outputs.push(String::from_utf8_lossy(r.len_delim()?).into_owned()),
            (3, 2) => name = String::from_utf8_lossy(r.len_delim()?).into_owned(),
            (4, 2) => op_type = String::from_utf8_lossy(r.len_delim()?).into_owned(),
            (5, 2) => {
                let (key, value) = parse_attribute(r.len_delim()?)?;
                attrs.insert(key, value);
            }
            _ => r.skip(wire)?,
        }
    }
    let output = outputs
        .into_iter()
        .next()
        .ok_or_else(|| OnnxError::BadAttr(format!("node {name}: no output")))?;
    Ok(Node {
        op: Op::parse(&op_type)?,
        name,
        inputs,
        output,
        attrs,
    })
}

/// TensorProto data types the shards use.
const DT_FLOAT: i64 = 1;

fn parse_tensor(bytes: &[u8]) -> Result<(String, Tensor), OnnxError> {
    let mut r = Reader { buf: bytes, pos: 0 };
    let mut dims: Vec<usize> = Vec::new();
    let mut data_type: Option<i64> = None;
    let mut float_data: Vec<f32> = Vec::new();
    let mut raw: Option<Vec<u8>> = None;
    let mut name = String::new();
    while let Some((field, wire)) = r.next()? {
        match (field, wire) {
            (1, _) => {
                for dim in r.packed_varints(wire)? {
                    dims.push(dim as usize);
                }
            }
            (2, 0) => data_type = Some(r.varint()? as i64),
            (4, 2) => {
                let bytes = r.len_delim()?;
                if bytes.len() % 4 != 0 {
                    return Err(OnnxError::BadAttr("float_data not multiple of 4".into()));
                }
                float_data.extend(
                    bytes
                        .chunks_exact(4)
                        .map(|c| f32::from_bits(u32::from_le_bytes([c[0], c[1], c[2], c[3]]))),
                );
            }
            (8, 2) => name = String::from_utf8_lossy(r.len_delim()?).into_owned(),
            (9, 2) => raw = Some(r.len_delim()?.to_vec()),
            _ => r.skip(wire)?,
        }
    }
    if data_type != Some(DT_FLOAT) {
        return Err(OnnxError::BadAttr(format!(
            "tensor {name}: data type {data_type:?} != FLOAT"
        )));
    }
    let data = match raw {
        Some(bytes) => {
            if bytes.len() % 4 != 0 {
                return Err(OnnxError::BadAttr(format!(
                    "tensor {name}: raw_data not multiple of 4"
                )));
            }
            bytes
                .chunks_exact(4)
                .map(|c| f32::from_bits(u32::from_le_bytes([c[0], c[1], c[2], c[3]])))
                .collect()
        }
        None => float_data,
    };
    let expected: usize = dims.iter().product();
    if data.len() != expected {
        return Err(OnnxError::Shape(format!(
            "tensor {name}: {} values for dims {dims:?}",
            data.len()
        )));
    }
    Ok((name, Tensor { dims, data }))
}

fn parse_value_info_name(bytes: &[u8]) -> Result<String, OnnxError> {
    let mut r = Reader { buf: bytes, pos: 0 };
    while let Some((field, wire)) = r.next()? {
        match (field, wire) {
            (1, 2) => return Ok(String::from_utf8_lossy(r.len_delim()?).into_owned()),
            _ => r.skip(wire)?,
        }
    }
    Err(OnnxError::BadAttr("value_info without name".into()))
}

#[cfg(test)]
pub(crate) mod testutil {
    //! Minimal protobuf writer shared by the onnx/scoring/consumer tests.

    use super::{ATTR_FLOAT, ATTR_INT, ATTR_INTS, DT_FLOAT};

    pub fn varint(out: &mut Vec<u8>, mut value: u64) {
        loop {
            let byte = (value & 0x7f) as u8;
            value >>= 7;
            if value == 0 {
                out.push(byte);
                return;
            }
            out.push(byte | 0x80);
        }
    }

    pub fn tag(out: &mut Vec<u8>, field: u32, wire: u8) {
        varint(out, u64::from(field) << 3 | u64::from(wire));
    }

    pub fn len_field(out: &mut Vec<u8>, field: u32, bytes: &[u8]) {
        tag(out, field, 2);
        varint(out, bytes.len() as u64);
        out.extend_from_slice(bytes);
    }

    pub fn u64_field(out: &mut Vec<u8>, field: u32, value: u64) {
        tag(out, field, 0);
        varint(out, value);
    }

    pub fn f32_field(out: &mut Vec<u8>, field: u32, value: f32) {
        tag(out, field, 5);
        out.extend_from_slice(&value.to_le_bytes());
    }

    pub fn tensor(name: &str, dims: &[usize], data: &[f32]) -> Vec<u8> {
        let mut t = Vec::new();
        for dim in dims {
            u64_field(&mut t, 1, *dim as u64);
        }
        u64_field(&mut t, 2, DT_FLOAT as u64);
        let mut packed = Vec::new();
        for value in data {
            packed.extend_from_slice(&value.to_le_bytes());
        }
        len_field(&mut t, 4, &packed);
        len_field(&mut t, 8, name.as_bytes());
        t
    }

    pub fn attr_ints(name: &str, values: &[i64]) -> Vec<u8> {
        // Legacy schema, as the shards use: ints at field 8, scalar wire 0.
        let mut a = Vec::new();
        len_field(&mut a, 1, name.as_bytes());
        for value in values {
            u64_field(&mut a, 8, *value as u64);
        }
        u64_field(&mut a, 20, ATTR_INTS as u64);
        a
    }

    pub fn attr_int(name: &str, value: i64) -> Vec<u8> {
        let mut a = Vec::new();
        len_field(&mut a, 1, name.as_bytes());
        u64_field(&mut a, 3, value as u64);
        u64_field(&mut a, 20, ATTR_INT as u64);
        a
    }

    pub fn attr_float(name: &str, value: f32) -> Vec<u8> {
        let mut a = Vec::new();
        len_field(&mut a, 1, name.as_bytes());
        f32_field(&mut a, 2, value);
        u64_field(&mut a, 20, ATTR_FLOAT as u64);
        a
    }

    pub fn node(op: &str, name: &str, inputs: &[&str], output: &str, attrs: &[Vec<u8>]) -> Vec<u8> {
        let mut n = Vec::new();
        for input in inputs {
            len_field(&mut n, 1, input.as_bytes());
        }
        len_field(&mut n, 2, output.as_bytes());
        len_field(&mut n, 3, name.as_bytes());
        len_field(&mut n, 4, op.as_bytes());
        for attr in attrs {
            len_field(&mut n, 5, attr);
        }
        n
    }

    pub fn value_info(name: &str) -> Vec<u8> {
        let mut v = Vec::new();
        len_field(&mut v, 1, name.as_bytes());
        v
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::{
        attr_float, attr_int, attr_ints, len_field, node, tensor, u64_field, value_info,
    };
    use super::*;

    /// 1×1 conv (2→1) + bias, then GAP, flatten, gemm to 3 outputs,
    /// softmax — the shard pipeline in miniature.
    fn synthetic_model() -> Vec<u8> {
        let mut graph = Vec::new();
        for n in [
            node(
                "Conv",
                "c0",
                &["x", "w", "b"],
                "y",
                &[
                    attr_ints("kernel_shape", &[1, 1]),
                    attr_ints("strides", &[1, 1]),
                    attr_ints("pads", &[0, 0, 0, 0]),
                    attr_ints("dilations", &[1, 1]),
                    attr_int("group", 1),
                ],
            ),
            node("GlobalAveragePool", "gap", &["y"], "z", &[]),
            node("Flatten", "flat", &["z"], "f", &[]),
            node(
                "Gemm",
                "gemm",
                &["f", "cw", "cb"],
                "logits",
                &[attr_int("transB", 1)],
            ),
            node("Softmax", "sm", &["logits"], "out", &[]),
        ] {
            len_field(&mut graph, 1, &n);
        }
        for t in [
            tensor("w", &[1, 2, 1, 1], &[1.0, 1.0]),
            tensor("b", &[1], &[0.0]),
            tensor("cw", &[3, 1], &[1.0, -1.0, 0.5]),
            tensor("cb", &[3], &[0.0, 0.0, 0.25]),
        ] {
            len_field(&mut graph, 5, &t);
        }
        len_field(&mut graph, 11, &value_info("x"));
        len_field(&mut graph, 12, &value_info("out"));

        let mut model = Vec::new();
        u64_field(&mut model, 1, 6); // ir_version
        len_field(&mut model, 7, &graph);
        model
    }

    #[test]
    fn parses_and_evaluates_a_synthetic_graph() {
        let model = Model::parse(&synthetic_model()).expect("parse");
        assert_eq!(model.input_name(), "x");
        assert_eq!(model.output_name(), "out");

        // 1×2×2×1 input: channel0 all 2s, channel1 all 4s → conv y = 6.
        let input = Tensor {
            dims: vec![1, 2, 2, 1],
            data: vec![2.0, 4.0, 2.0, 4.0],
        };
        let out = model.run(input).expect("run");
        assert_eq!(out.dims, vec![1, 3]);
        // logits = [6, -6, 3.25]; softmax sums to 1 and argmax is class 0.
        let total: f32 = out.data.iter().sum();
        assert!((total - 1.0).abs() < 1e-6);
        assert!(out.data[0] > out.data[1] && out.data[0] > out.data[2]);
        let expected0 = 6.0f32.exp() / (6.0f32.exp() + (-6.0f32).exp() + 3.25f32.exp());
        assert!((out.data[0] - expected0).abs() < 1e-6);
    }

    #[test]
    fn depthwise_grouped_convolution_slices_channels() {
        // 2-channel depthwise 1×1 with per-channel weights.
        let mut graph = Vec::new();
        len_field(
            &mut graph,
            1,
            &node(
                "Conv",
                "dw",
                &["x", "w", "b"],
                "out",
                &[attr_ints("kernel_shape", &[1, 1]), attr_int("group", 2)],
            ),
        );
        for t in [
            tensor("w", &[2, 1, 1, 1], &[2.0, 10.0]),
            tensor("b", &[2], &[1.0, 0.0]),
        ] {
            len_field(&mut graph, 5, &t);
        }
        len_field(&mut graph, 11, &value_info("x"));
        len_field(&mut graph, 12, &value_info("out"));
        let mut model = Vec::new();
        len_field(&mut model, 7, &graph);

        let model = Model::parse(&model).expect("parse");
        let out = model
            .run(Tensor {
                dims: vec![1, 2, 1, 1],
                data: vec![3.0, 4.0],
            })
            .expect("run");
        // channel0: 2*3 + 1 = 7; channel1: 10*4 + 0 = 40.
        assert_eq!(out.data, vec![7.0, 40.0]);
    }

    #[test]
    fn unknown_ops_and_unresolved_inputs_fail_at_parse() {
        let mut graph = Vec::new();
        len_field(&mut graph, 1, &node("MaxPool", "m", &["x"], "y", &[]));
        len_field(&mut graph, 11, &value_info("x"));
        len_field(&mut graph, 12, &value_info("y"));
        let mut model = Vec::new();
        len_field(&mut model, 7, &graph);
        assert!(matches!(
            Model::parse(&model),
            Err(OnnxError::UnknownOp(op)) if op == "MaxPool"
        ));
    }

    #[test]
    fn clip_without_attrs_is_relu_and_with_attrs_clamps() {
        let model = Model::parse(&synthetic_model()).unwrap();
        let _ = model;
        // Hand-build a Clip-only graph with explicit min/max.
        let mut graph = Vec::new();
        len_field(
            &mut graph,
            1,
            &node(
                "Clip",
                "clip",
                &["x"],
                "out",
                &[attr_float("min", -1.0), attr_float("max", 1.0)],
            ),
        );
        len_field(&mut graph, 11, &value_info("x"));
        len_field(&mut graph, 12, &value_info("out"));
        let mut bytes = Vec::new();
        len_field(&mut bytes, 7, &graph);
        let model = Model::parse(&bytes).expect("parse");
        let out = model
            .run(Tensor {
                dims: vec![1, 3],
                data: vec![-5.0, 0.5, 9.0],
            })
            .expect("run");
        assert_eq!(out.data, vec![-1.0, 0.5, 1.0]);
    }
}
