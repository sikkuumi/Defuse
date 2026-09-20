/*
 * THE C++ MUTATORS, WHICH C++ DID NOT HAVE.
 *
 * Every other language here declares `mutators` - the methods that dirty the
 * object they are called ON rather than returning a dirty value. C has no
 * methods so C_DICTIONARY declares none, and CPP_DICTIONARY spreads
 * C_DICTIONARY, so C++ silently inherited an empty list.
 *
 * `append` was already listed as a PROPAGATOR, which is the other direction
 * entirely: it carries taint from the receiver out to the result. So
 * `dirty.append(" -v")` traced and `clean.append(dirty)` did not, and being
 * listed in one direction looked from the outside like being handled. That is
 * the most expensive kind of gap - the one that looks covered.
 *
 * The three methods below are what got added. Nothing else: push_back,
 * emplace_back and the container form of insert stay out until there is a
 * matching elementMutators list, because without one the containerGuess rule
 * cannot do its job and a container written many times then read back once
 * would come out claiming a proof it has not got. Taint into a std::vector is
 * a documented miss, not a quiet one - see the last case.
 */

#include <cstdlib>
#include <string>
#include <vector>

// append: the method spelling of concatenation.
void throughAppend(char **argv) {
    std::string cmd = "gzip ";
    cmd.append(argv[1]);
    // EXPECT-FLOW command-injection
    std::system(cmd.c_str());
}

// assign: replaces the contents wholesale, so the receiver becomes the value.
void throughAssign(char **argv) {
    std::string cmd;
    cmd.assign(argv[1]);
    // EXPECT-FLOW command-injection
    std::system(cmd.c_str());
}

// replace: substitutes a range, leaving the rest of the string in place.
void throughReplace(char **argv) {
    std::string cmd = "ping XXXXXX";
    cmd.replace(5, 6, argv[1]);
    // EXPECT-FLOW command-injection
    std::system(cmd.c_str());
}

/*
 * A container element write. A DOCUMENTED MISS, unannotated on purpose.
 *
 * push_back would be easy to add to the mutators list and it would be wrong to
 * add it alone: element writes need an elementMutators entry so the
 * containerGuess rule can downgrade a read back out of a container that took
 * several writes. Adding the first list without the second would turn this
 * into a flow-verified finding - a proof claimed over exactly the ambiguity
 * that rule exists to refuse.
 *
 * Silent and written down beats loud and overclaiming, until both lists exist.
 */
void intoAVectorIsMissed(char **argv) {
    std::vector<std::string> parts;
    parts.push_back("tar");
    parts.push_back(argv[1]);
    std::string cmd = parts[0] + " " + parts[1];
    std::system(cmd.c_str());
}
