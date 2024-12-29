#!/usr/bin/env python3

import csv


class MobileCodeSearcher:
    """
    Class to search for network information based on MCC (Mobile Country Code) and MNC (Mobile Network Code).

    :param csv_file_path: Path to the CSV file containing MCC and MNC data.
    """

    def __init__(self, csv_file_path):
        self.csv_file_path = csv_file_path
        self.data = []
        self._load_data()

    def _load_data(self):
        """
        Loads data from the specified CSV file into the `data` attribute.
        """
        with open(self.csv_file_path, newline="", encoding="utf-8") as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                self.data.append(row)

    def search_by_mcc(self, mcc):
        """
        Searches for all countries associated with a given MCC (Mobile Country Code).

        :param mcc: MCC code to search for.
        :return: List of countries corresponding to the provided MCC.
        """
        results = list(set([row["Country"] for row in self.data if row["MCC"] == mcc]))
        return results

    def search_by_mcc_mnc(self, mcc, mnc):
        """
        Searches for network information based on a given MCC and MNC (Mobile Network Code).

        :param mcc: MCC code to search for.
        :param mnc: MNC code to search for.
        :return: List of dictionaries with country and network details for the provided MCC and MNC.
        """
        results = [row for row in self.data if row["MCC"] == mcc and row["MNC"] == mnc]
        return [{"Country": row["Country"], "Network": row["Network"]} for row in results]


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Search MCC and MNC information from a CSV file.")
    parser.add_argument("csv_file", help="Path to the CSV file containing MCC and MNC data.")
    parser.add_argument("--mcc", help="MCC code to search for.")
    parser.add_argument("--mnc", help="MNC code to search for. Requires --mcc.")

    args = parser.parse_args()

    searcher = MobileCodeSearcher(args.csv_file)

    if args.mcc and args.mnc:
        results = searcher.search_by_mcc_mnc(args.mcc, args.mnc)
        if results:
            print("Results found:")
            for result in results:
                print(result)
        else:
            print("No results found for MCC={} and MNC={}".format(args.mcc, args.mnc))
    elif args.mcc:
        results = searcher.search_by_mcc(args.mcc)
        if results:
            print("Countries found:")
            for country in results:
                print(country)
        else:
            print("No results found for MCC={}".format(args.mcc))
    else:
        print("You must provide at least an MCC to perform a search.")


if __name__ == "__main__":
    main()
