//! Word lists for the username generator: friendly adjectives and nouns, lowercase ASCII, 3 to 9
//! letters, written for Passyble. Usernames are not secrets: the lists only need enough variety
//! that two generated names rarely clash.

pub(crate) const ADJECTIVES: &[&str] = &[
    "able", "agile", "amber", "ample", "arctic", "azure", "balmy", "bold", "brave", "breezy",
    "bright", "brisk", "broad", "bubbly", "calm", "candid", "cheery", "chief", "civic", "clean",
    "clear", "clever", "cloudy", "cobalt", "comfy", "cool", "cosmic", "cozy", "crisp", "curious",
    "curly", "dandy", "dapper", "daring", "deft", "dewy", "direct", "dreamy", "dusky", "eager",
    "early", "earnest", "easy", "elated", "elfin", "epic", "even", "exact", "fabled", "fair",
    "famous", "fancy", "fast", "fearless", "fierce", "fine", "firm", "fleet", "fluffy", "fond",
    "frank", "free", "fresh", "frosty", "funny", "fuzzy", "gallant", "gentle", "giant", "gifted",
    "glad", "gleaming", "global", "golden", "grand", "great", "green", "happy", "hardy", "hazy",
    "hearty", "heroic", "honest", "humble", "icy", "ideal", "jade", "jolly", "jovial", "joyful",
    "keen", "kind", "kindly", "lavish", "lively", "lofty", "loyal", "lucid", "lucky", "lunar",
    "magic", "major", "mellow", "merry", "mighty", "mild", "minty", "misty", "modern", "modest",
    "mossy", "nimble", "noble", "nordic", "novel", "oaken", "olive", "open", "orange", "peppy",
    "perky", "placid", "plucky", "polar", "polite", "prime", "proud", "quick", "quiet", "rapid",
    "rare", "ready", "regal", "rosy", "royal", "rustic", "sandy", "savvy", "scarlet", "serene",
    "sharp", "shiny", "silent", "silky", "silver", "simple", "sleek", "smart", "smooth", "snowy",
    "social", "solar", "solid", "sonic", "spry", "stable", "steady", "stellar", "stormy", "sturdy",
    "sunny", "super", "swift", "tidy", "tranquil", "true", "trusty", "upbeat", "urban", "valiant",
    "velvet", "vivid", "warm", "wise", "witty", "wooden", "worthy", "young", "zany", "zesty",
    "zippy", "amiable", "astral", "blithe", "bonny", "chipper", "coastal", "crafty", "dazzling",
    "devoted", "dynamic", "electric", "emerald", "festive", "fiery", "fluent", "glowing",
    "graceful", "hidden", "indigo", "jaunty", "lush", "maroon", "mystic", "natural", "neat",
    "nifty", "patient", "pearly", "plush", "radiant", "rugged", "sage", "scenic", "sincere",
    "spirited", "sublime", "sunlit", "tender", "thrifty", "timely", "topaz", "vital", "wild",
    "windy", "wondrous",
];

pub(crate) const NOUNS: &[&str] = &[
    "otter", "badger", "beaver", "bison", "bobcat", "buffalo", "camel", "cheetah", "cobra",
    "condor", "cougar", "coyote", "crane", "cricket", "dingo", "dolphin", "donkey", "eagle",
    "egret", "falcon", "ferret", "finch", "fox", "gazelle", "gecko", "gibbon", "giraffe", "goose",
    "gopher", "heron", "hippo", "hornet", "husky", "ibex", "iguana", "impala", "jackal", "jaguar",
    "kestrel", "kiwi", "koala", "lemur", "leopard", "lion", "lizard", "llama", "lobster", "lynx",
    "macaw", "magpie", "mallard", "manatee", "marmot", "marten", "meerkat", "mink", "mole",
    "moose", "narwhal", "newt", "ocelot", "octopus", "orca", "osprey", "ostrich", "owl", "panda",
    "panther", "parrot", "pelican", "penguin", "pigeon", "puffin", "puma", "quail", "rabbit",
    "raccoon", "raven", "robin", "salmon", "seal", "shark", "sparrow", "squid", "stork", "swan",
    "tapir", "tiger", "toucan", "trout", "turtle", "viper", "walrus", "weasel", "whale", "wolf",
    "wombat", "yak", "zebra", "alpaca", "antelope", "beetle", "bluejay", "bunny", "canary",
    "caribou", "chipmunk", "cicada", "corgi", "dove", "dragon", "duck", "elk", "emu", "fawn",
    "firefly", "flamingo", "gator", "grizzly", "hamster", "hare", "hawk", "hedgehog", "jay",
    "kitten", "ladybug", "lark", "mantis", "mongoose", "moth", "mustang", "oriole", "oyster",
    "pony", "possum", "quokka", "reindeer", "rhino", "seahorse", "sloth", "snail", "stallion",
    "starling", "swallow", "tadpole", "terrier", "toad", "wren", "acorn", "aspen", "birch",
    "breeze", "brook", "canyon", "cedar", "cliff", "cloud", "comet", "coral", "cove", "creek",
    "delta", "dune", "ember", "fern", "fjord", "forest", "frost", "galaxy", "geyser", "glacier",
    "grove", "harbor", "island", "jungle", "lagoon", "lake", "maple", "meadow", "mesa", "meteor",
    "moon", "nebula", "oak", "oasis", "orbit", "pebble", "pine", "planet", "prairie", "quartz",
    "rain", "reef", "ridge", "river", "rocket", "sierra", "sky", "spruce", "star", "storm",
    "summit", "sun", "thunder", "tundra", "valley", "willow", "badlands", "bamboo", "beacon",
    "blossom", "boulder", "cactus", "cascade", "clover", "crater", "crystal", "daisy", "dawn",
    "dusk", "falls", "garnet", "horizon", "iris", "lantern", "lotus", "marsh", "mist", "orchid",
    "peak", "poppy", "rapids", "sequoia", "shore", "spring", "sunrise", "tide", "tulip", "wave",
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn lists_are_clean_and_unique() {
        for list in [ADJECTIVES, NOUNS] {
            let set: BTreeSet<&str> = list.iter().copied().collect();
            assert_eq!(set.len(), list.len(), "duplicate word");
            for w in list {
                assert!(
                    (3..=9).contains(&w.len()) && w.bytes().all(|b| b.is_ascii_lowercase()),
                    "bad word {w:?}"
                );
            }
            assert!(list.len() >= 200);
        }
    }
}
