/**
 * Canonical wordlists for the deterministic default identity (see kunjiHandle.js).
 *
 * ⚠️ These lists are a cross-RP rendering CONTRACT. The mapping uses each list's
 * length (modulo), so reordering, adding, or removing words changes which name an
 * existing `sub` resolves to — i.e. it re-skins every user's default display name.
 * That is cosmetic (never a lockout — `sub` stays the account key), but any change
 * should be treated as a versioned break and mirrored in docs/discoverable-login.md.
 * Words are intentionally friendly and brand-neutral (nature / positive qualities).
 */

export const ADJECTIVES =
  `amber azure bold brave bright brisk calm candid cheerful clever cobalt cosmic cozy crimson crisp curious daring dawn deft eager early easy electric elegant ember fabled fair fearless fleet fond free fresh gentle gilded glad gleaming golden graceful grand hardy hazel hidden honest humble indigo jade jolly jovial keen kind lively loyal lucid lunar marble mellow merry mighty mild misty modest noble nimble opal polar prime proud quick quiet radiant rapid ready regal rosy ruby rustic sage scarlet serene sharp shy silent silver sleek smooth snowy solar spry stellar sturdy sunny swift tame tidal timber tranquil true twilight valiant velvet verdant vivid warm wild willing windy winter wise witty zealous amethyst autumn breezy coral dusky frosty gallant ivory lilac mossy ochre plucky saffron teal umber vernal wandering woven`.split(
    /\s+/,
  );

export const NOUNS =
  `otter fox heron wren lark finch robin sparrow falcon hawk owl raven crane swan ibis egret plover swift martin kestrel badger beaver marten lynx puma ocelot panther jaguar leopard cheetah bison moose elk stag ibex gazelle oryx antelope mustang pony foal hare rabbit marmot gopher vole shrew mole hedgehog pangolin tapir capybara seal walrus dolphin porpoise narwhal orca manta marlin tuna salmon trout perch koi carp eel ray urchin anemone nautilus octopus squid crab prawn newt gecko skink iguana chameleon tortoise terrapin cobra viper python mamba monitor dragon phoenix griffin sphinx comet nebula quasar pulsar nova meteor aurora zenith summit ridge canyon mesa fjord delta lagoon atoll reef dune oasis glacier tundra savanna prairie meadow grove thicket willow cedar birch maple alder aspen juniper cypress sequoia redwood banyan`.split(
    /\s+/,
  );
