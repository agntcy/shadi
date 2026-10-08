// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! The update rule a team derives in ASSEMBLY: an expression over a class's
//! named local quantities, which each agent applies itself in CONVERGE.
//!
//! A rule is checked by probing: it and the class's reference rule are both
//! evaluated on random inputs, so equivalent rewritings of the same rule
//! agree without any symbolic algebra.

use std::collections::BTreeMap;

use crate::engines::converge::UpdateClass;

/// A class's named local quantities and their current values.
pub type Quantities = BTreeMap<&'static str, f64>;

/// Points a rule is probed at.
const PROBES: usize = 64;

/// The `UPDATE <expression>` line of an ASSEMBLY reply; the first one wins.
/// A leading `<name> =` is dropped, since models often write an assignment.
pub fn update_line(text: &str) -> Option<&str> {
    for line in text.lines() {
        let trimmed = line.trim();
        let Some(rest) = trimmed
            .strip_prefix("UPDATE")
            .filter(|rest| rest.starts_with([' ', ':', '=']))
        else {
            continue;
        };
        let rest = rest
            .trim_start_matches([' ', ':', '='])
            .trim()
            .trim_matches('`')
            .trim();
        let rest = strip_assignment(rest);
        if !rest.is_empty() {
            return Some(rest);
        }
    }
    None
}

fn strip_assignment(text: &str) -> &str {
    let name_end = text
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(text.len());
    let after = text[name_end..].trim_start();
    match after.strip_prefix('=') {
        Some(rhs) if name_end > 0 && !rhs.starts_with('=') => rhs.trim(),
        _ => text,
    }
}

/// A parsed rule that reads only names from its class.
#[derive(Clone, Debug, PartialEq)]
pub struct UpdateRule {
    source: String,
    expr: Expr,
}

impl UpdateRule {
    /// Parse `source`, refusing any name outside `names`.
    pub fn parse(source: &str, names: &[&str]) -> Result<Self, String> {
        let mut parser = Parser {
            tokens: tokenize(source)?,
            at: 0,
            names,
        };
        let expr = parser.expr()?;
        if let Some(token) = parser.tokens.get(parser.at) {
            return Err(format!("unexpected {token:?} in update rule"));
        }
        Ok(Self {
            source: source.to_string(),
            expr,
        })
    }

    pub fn source(&self) -> &str {
        &self.source
    }

    /// The next value this rule gives for `quantities`.
    pub fn eval(&self, quantities: &Quantities) -> Result<f64, String> {
        let value = self.expr.eval(quantities)?;
        if value.is_finite() {
            Ok(value)
        } else {
            Err("update rule gave a value that is not a finite number".to_string())
        }
    }
}

/// How a submitted rule compares with its class's reference rule.
#[derive(Clone, Debug, PartialEq)]
pub enum Derivation {
    /// No `UPDATE` line.
    Missing,
    /// An `UPDATE` line that does not parse over the class's names.
    Invalid(String),
    /// Parses but disagrees with the reference somewhere it was probed.
    Differs { worst_gap: f64 },
    /// Agrees with the reference at every probe.
    Matches,
}

impl Derivation {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Invalid(_) => "invalid",
            Self::Differs { .. } => "differs",
            Self::Matches => "matches",
        }
    }
}

/// Parse an agent's ASSEMBLY reply for class `C` and score its rule.
pub fn derive<C: UpdateClass>(reply: &str) -> (Option<UpdateRule>, Derivation) {
    let Some(line) = update_line(reply) else {
        return (None, Derivation::Missing);
    };
    match UpdateRule::parse(line, C::QUANTITIES) {
        Ok(rule) => {
            let verdict = verify::<C>(&rule);
            (Some(rule), verdict)
        }
        Err(err) => (None, Derivation::Invalid(err)),
    }
}

/// Compare `rule` with `C`'s reference rule at random points.
pub fn verify<C: UpdateClass>(rule: &UpdateRule) -> Derivation {
    let mut probe = Probe::new(0x5eed_5a0d_1a7e);
    let mut worst_gap = 0.0_f64;
    for _ in 0..PROBES {
        let point = C::probe(&mut probe);
        let reference = C::reference(&point);
        let gap = match rule.eval(&point) {
            Ok(value) => (value - reference).abs(),
            Err(_) => f64::INFINITY,
        };
        if gap > 1e-9 * reference.abs().max(1.0) {
            worst_gap = worst_gap.max(gap);
        }
    }
    if worst_gap > 0.0 {
        Derivation::Differs { worst_gap }
    } else {
        Derivation::Matches
    }
}

/// Deterministic draws for probing, so a verdict never depends on the run.
pub struct Probe(u64);

impl Probe {
    pub fn new(seed: u64) -> Self {
        Self(seed.max(1))
    }

    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    /// Uniform in `[low, high)`.
    pub fn uniform(&mut self, low: f64, high: f64) -> f64 {
        let unit = (self.next() >> 11) as f64 / (1u64 << 53) as f64;
        low + unit * (high - low)
    }

    /// A whole number in `[low, high]`.
    pub fn whole(&mut self, low: u32, high: u32) -> f64 {
        let span = u64::from(high - low) + 1;
        f64::from(low) + (self.next() % span) as f64
    }
}

#[derive(Clone, Debug, PartialEq)]
enum Expr {
    Number(f64),
    Name(String),
    Neg(Box<Expr>),
    Binary(Box<Expr>, char, Box<Expr>),
    Call(String, Vec<Expr>),
}

impl Expr {
    fn eval(&self, quantities: &Quantities) -> Result<f64, String> {
        Ok(match self {
            Self::Number(value) => *value,
            Self::Name(name) => *quantities
                .get(name.as_str())
                .ok_or_else(|| format!("no value for {name}"))?,
            Self::Neg(inner) => -inner.eval(quantities)?,
            Self::Binary(left, op, right) => {
                let (l, r) = (left.eval(quantities)?, right.eval(quantities)?);
                match op {
                    '+' => l + r,
                    '-' => l - r,
                    '*' => l * r,
                    _ => l / r,
                }
            }
            Self::Call(function, args) => {
                let args = args
                    .iter()
                    .map(|arg| arg.eval(quantities))
                    .collect::<Result<Vec<_>, _>>()?;
                match (function.as_str(), args.as_slice()) {
                    ("max", [first, rest @ ..]) => rest.iter().fold(*first, |a, b| a.max(*b)),
                    ("min", [first, rest @ ..]) => rest.iter().fold(*first, |a, b| a.min(*b)),
                    ("abs", [x]) => x.abs(),
                    ("clamp", [x, low, high]) => x.max(*low).min(*high),
                    _ => return Err(format!("{function} cannot take {} values", args.len())),
                }
            }
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
enum Token {
    Number(f64),
    Name(String),
    Symbol(char),
}

fn tokenize(source: &str) -> Result<Vec<Token>, String> {
    let chars: Vec<char> = source.chars().collect();
    let mut tokens = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
        } else if c.is_ascii_digit() || c == '.' {
            let start = i;
            while i < chars.len() && (chars[i].is_ascii_digit() || chars[i] == '.') {
                i += 1;
            }
            if i < chars.len() && matches!(chars[i], 'e' | 'E') {
                i += 1;
                if i < chars.len() && matches!(chars[i], '+' | '-') {
                    i += 1;
                }
                while i < chars.len() && chars[i].is_ascii_digit() {
                    i += 1;
                }
            }
            let text: String = chars[start..i].iter().collect();
            let value = text
                .parse()
                .map_err(|_| format!("{text} is not a number"))?;
            tokens.push(Token::Number(value));
        } else if c.is_ascii_alphabetic() || c == '_' {
            let start = i;
            while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            tokens.push(Token::Name(chars[start..i].iter().collect()));
        } else if "+-*/(),".contains(c) {
            tokens.push(Token::Symbol(c));
            i += 1;
        } else {
            return Err(format!("{c:?} is not allowed in an update rule"));
        }
    }
    Ok(tokens)
}

const FUNCTIONS: [&str; 4] = ["max", "min", "abs", "clamp"];

struct Parser<'a> {
    tokens: Vec<Token>,
    at: usize,
    names: &'a [&'a str],
}

impl Parser<'_> {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.at)
    }

    fn eat(&mut self, symbol: char) -> bool {
        if self.peek() == Some(&Token::Symbol(symbol)) {
            self.at += 1;
            true
        } else {
            false
        }
    }

    fn expr(&mut self) -> Result<Expr, String> {
        let mut left = self.term()?;
        loop {
            let op = if self.eat('+') {
                '+'
            } else if self.eat('-') {
                '-'
            } else {
                return Ok(left);
            };
            left = Expr::Binary(Box::new(left), op, Box::new(self.term()?));
        }
    }

    fn term(&mut self) -> Result<Expr, String> {
        let mut left = self.factor()?;
        loop {
            let op = if self.eat('*') {
                '*'
            } else if self.eat('/') {
                '/'
            } else {
                return Ok(left);
            };
            left = Expr::Binary(Box::new(left), op, Box::new(self.factor()?));
        }
    }

    fn factor(&mut self) -> Result<Expr, String> {
        if self.eat('-') {
            return Ok(Expr::Neg(Box::new(self.factor()?)));
        }
        if self.eat('+') {
            return self.factor();
        }
        if self.eat('(') {
            let inner = self.expr()?;
            return if self.eat(')') {
                Ok(inner)
            } else {
                Err("missing ) in update rule".to_string())
            };
        }
        match self.tokens.get(self.at).cloned() {
            Some(Token::Number(value)) => {
                self.at += 1;
                Ok(Expr::Number(value))
            }
            Some(Token::Name(name)) => {
                self.at += 1;
                if self.eat('(') {
                    return self.call(name);
                }
                if self.names.contains(&name.as_str()) {
                    Ok(Expr::Name(name))
                } else {
                    Err(format!(
                        "{name} is not a quantity of this class (use {})",
                        self.names.join(", ")
                    ))
                }
            }
            Some(token) => Err(format!("unexpected {token:?} in update rule")),
            None => Err("update rule ends early".to_string()),
        }
    }

    fn call(&mut self, function: String) -> Result<Expr, String> {
        if !FUNCTIONS.contains(&function.as_str()) {
            return Err(format!(
                "{function} is not a function (use {})",
                FUNCTIONS.join(", ")
            ));
        }
        let mut args = vec![self.expr()?];
        while self.eat(',') {
            args.push(self.expr()?);
        }
        if !self.eat(')') {
            return Err(format!("missing ) after the arguments of {function}"));
        }
        Ok(Expr::Call(function, args))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engines::cascade::CascadeEngine;
    use crate::engines::preference::PreferenceEngine;
    use crate::engines::resource::ResourceEngine;

    const NAMES: &[&str] = &["a", "b", "c"];

    fn eval(source: &str) -> Result<f64, String> {
        let q = Quantities::from([("a", 2.0), ("b", 3.0), ("c", -4.0)]);
        UpdateRule::parse(source, NAMES)?.eval(&q)
    }

    #[test]
    fn expressions_follow_arithmetic_precedence() {
        assert_eq!(eval("a + b * c"), Ok(-10.0));
        assert_eq!(eval("(a + b) * c"), Ok(-20.0));
        assert_eq!(eval("-a - -b"), Ok(1.0));
        assert_eq!(eval("a / b / 2"), Ok(1.0 / 3.0));
        assert_eq!(eval("1.5e1 + .5"), Ok(15.5));
        assert_eq!(eval("2e-1 + 1E+1"), Ok(10.2));
        assert_eq!(eval("+a"), Ok(2.0));
    }

    #[test]
    fn functions_cover_the_reference_rules() {
        assert_eq!(eval("max(c, 0)"), Ok(0.0));
        assert_eq!(eval("min(a, b, c)"), Ok(-4.0));
        assert_eq!(eval("abs(c)"), Ok(4.0));
        assert_eq!(eval("clamp(b * 10, 0, a)"), Ok(2.0));
    }

    #[test]
    fn unknown_names_and_bad_syntax_are_refused() {
        let err = eval("a + d").unwrap_err();
        assert!(
            err.contains("d is not a quantity") && err.contains("a, b, c"),
            "{err}"
        );
        assert!(eval("sqrt(a)").unwrap_err().contains("not a function"));
        assert!(eval("clamp(a, b)").unwrap_err().contains("cannot take 2"));
        assert!(eval("a b").is_err());
        assert!(eval("(a + b").is_err());
        assert!(eval("a ^ b").is_err());
        assert!(eval("a / (b - 3)").unwrap_err().contains("finite"));
        assert!(eval("* a").unwrap_err().contains("unexpected"));
        assert!(eval("a +").unwrap_err().contains("ends early"));
        assert!(eval("max(a, b").unwrap_err().contains("missing )"));
    }

    #[test]
    fn the_update_line_is_found_after_prose() {
        let reply = "We model it as a line graph.\nCLASS preference\nUPDATE: `next = (a + b)`\n";
        assert_eq!(update_line(reply), Some("(a + b)"));
        assert_eq!(update_line("UPDATE a == b"), Some("a == b"));
        assert_eq!(update_line("UPDATES a\nno rule here"), None);
        assert_eq!(update_line("UPDATE   \nUPDATE a"), Some("a"));
        assert_eq!(update_line("UPDATE :\nUPDATE = b"), Some("b"));
    }

    #[test]
    fn preference_rules_are_scored_by_probing() {
        let reference = "UPDATE (target + 2*beta*neighbour_sum) / (1 + 2*beta*degree)";
        assert_eq!(derive::<PreferenceEngine>(reference).1, Derivation::Matches);
        let rewritten = "UPDATE target/(1+2*beta*degree) + neighbour_sum*2*beta/(1+2*beta*degree)";
        assert_eq!(derive::<PreferenceEngine>(rewritten).1, Derivation::Matches);
        let keeps_state = "UPDATE (state + 2*beta*neighbour_sum) / (1 + 2*beta*degree)";
        assert!(matches!(
            derive::<PreferenceEngine>(keeps_state).1,
            Derivation::Differs { worst_gap } if worst_gap > 0.0
        ));
        assert_eq!(
            derive::<PreferenceEngine>("CLASS preference").1,
            Derivation::Missing
        );
        // A rule that cannot be evaluated somewhere does not match there.
        let undefined = "UPDATE target / (degree - degree)";
        assert!(matches!(
            derive::<PreferenceEngine>(undefined).1,
            Derivation::Differs { worst_gap } if worst_gap.is_infinite()
        ));
        let (rule, verdict) = derive::<PreferenceEngine>("UPDATE z_i + 1");
        assert!(rule.is_none());
        assert!(matches!(verdict, Derivation::Invalid(err) if err.contains("z_i")));
    }

    #[test]
    fn cascade_and_resource_need_their_bounds() {
        let order = "UPDATE (max(0, target_inventory + lead*demand - inventory - pipeline) \
                     + gamma*last_order + rho*previous_demand) / (1 + gamma + rho)";
        assert_eq!(derive::<CascadeEngine>(order).1, Derivation::Matches);
        let unbounded = order.replace("max(0, ", "(");
        assert!(matches!(
            derive::<CascadeEngine>(&unbounded).1,
            Derivation::Differs { .. }
        ));

        let take = "UPDATE clamp(extraction + eta*((desired - extraction) - price), 0, stock)";
        assert_eq!(derive::<ResourceEngine>(take).1, Derivation::Matches);
        let unclamped = "UPDATE extraction + eta*((desired - extraction) - price)";
        assert!(matches!(
            derive::<ResourceEngine>(unclamped).1,
            Derivation::Differs { .. }
        ));
    }

    #[test]
    fn probes_stay_inside_their_ranges() {
        let mut probe = Probe::new(7);
        for _ in 0..1000 {
            let x = probe.uniform(-1.0, 2.0);
            assert!((-1.0..2.0).contains(&x));
            let k = probe.whole(1, 3);
            assert!([1.0, 2.0, 3.0].contains(&k));
        }
        assert_eq!(Derivation::Differs { worst_gap: 1.0 }.as_str(), "differs");
        assert_eq!(Derivation::Invalid(String::new()).as_str(), "invalid");
    }
}
