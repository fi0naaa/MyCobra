#include <iostream>

using namespace std;
class PersonResultSet{
    public:

    int sub_int(int i){
        return i - 1;
    }

    int add_int(int i){
        return i + 1;
     }

    int max(int n1, int n2){
        int result;
        if (n1 > n2)
            result = n1;
        else
            result = n2;

        return result;
    }
};

class RoomResultSet {
  public:
    int sub_int(int i){
        return i - 1;
    }

    int add_int(int i){
        return i + 1;
     }
};

int max(int n1, int n2);
int min(int n1, int n2);
int b = 1;
//b = b + 1;
int main(){
  std::cout<< b;
  int durian = 10;
  PersonResultSet *aResultSet = new PersonResultSet();
  PersonResultSet *bResultSet = new PersonResultSet();
  PersonResultSet *cResultSet = new PersonResultSet();

  PersonResultSet *eResultSet = new PersonResultSet();
  PersonResultSet *fResultSet = new PersonResultSet();
  PersonResultSet *gResultSet = new PersonResultSet();

  durian = aResultSet->add_int(durian);
  durian = bResultSet->sub_int(durian);
  durian = cResultSet->sub_int(durian);

  int jack = 16;
  jack = eResultSet->add_int(durian);
  jack = bResultSet->sub_int(durian);
  jack = gResultSet->sub_int(durian);

//  cout << "durian=" << durian <<endl;
//  cout << "jack=" << jack <<endl;
  return 0;
}

int max(int n1, int n2){
    int result;
    if (n1 > n2)
        result = n1;
    else
        result = n2;

    return result;
}

int min(int n1, int n2){
    int result;
    if (n1 < n2)
        result = n1;
    else
        result = n2;

    return result;
}