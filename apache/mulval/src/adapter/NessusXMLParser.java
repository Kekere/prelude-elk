/*
Parse the nessus report in XML format and extracts vulnerability information for MulVAL.
Author(s) : Su Zhang
Copyright (C) 2011, Argus Cybersecurity Lab, Kansas State University

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

import java.io.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;

import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.Element;
import org.dom4j.io.*;
import org.json.simple.JSONObject;
import org.json.simple.JSONArray;

public class NessusXMLParser {

	public static void main(String[] args) {
		parseNessus(args[0]);
		
	}

	public static void parseNessus(String nessusReport) {
		HashMap<String, String> organization = new HashMap<String, String>();
		organization.put("name", "TSP");
		organization.put("description", "Ecole d'ingenieur du numerique");
		
		List<String> equipments = new ArrayList<String>();
		
		try {
			//FileWriter json = new FileWriter("countermeasure.json");
			String json = "countermeasure.json";
			JSONArray arrayd = new JSONArray();
			SAXReader saxReader = new SAXReader();
			FileWriter fr = new FileWriter("vulInfo.txt");
			Document document = saxReader.read(nessusReport);
			// Each entry is indexed by one cve_id
			List reportHost = document.selectNodes(
					"/*[local-name(.)='NessusClientData_v2']/*[local-name(.)='Report']/*[local-name(.)='ReportHost']");
			
			Iterator reportHostItrt = reportHost.iterator();
			while (reportHostItrt.hasNext()) {
				Element host = (Element) reportHostItrt.next();
				// Element iterator of each entry
				Iterator ei = host.elementIterator();
				// Put all of the subelements' names(subelement of entry) to an array list(subele)
				while (ei.hasNext()) {
					
					boolean hasCve = false;
					
					Element sube = (Element) ei.next();
					if(!sube.getName().equals("ReportItem"))
						continue;
					// A list of elements for each entry
					ArrayList<String> subele = new ArrayList<String>();
					Iterator reportItemItrt = sube.elementIterator();
					while(reportItemItrt.hasNext()) {
						Element reportItemElement = (Element) reportItemItrt.next();
						subele.add(reportItemElement.getName());
					}
					Iterator itr;
					if(subele.size() == 0 || (!subele.contains("cve") && !subele.contains("cvss3_vector")))
						continue;
					else if (!subele.contains("cve") && subele.contains("cvss3_vector")) {
						itr = sube.elementIterator("cvss3_vector");
					}
					else {
						itr= sube.elementIterator("cve");
						hasCve = true;
					}
					while(itr.hasNext()) {
						System.out.println("host name is: " + host.attribute(0).getText());
						
						//On ajoute Host
						fr.write(host.attribute(0).getText() + "\n");
						
						//On ajoute CVE
						Element cve = null;
						if (hasCve) {
							cve = (Element) itr.next();
							System.out.println(cve.getText());
							fr.write(cve.getText() + "\n");
						} else {
							System.out.println("No CVE ID associated");
							fr.write("CVE-XXXX-XXXX\n");
						}
						
						 
						Element cvss;
						if (subele.contains("cvss3_vector")) {
							if (hasCve) {
								cvss = (Element) sube.elementIterator("cvss3_vector").next();
							} else {
								cvss = (Element) itr.next();
							}
						} else {
							cvss = (Element) sube.elementIterator("cvss_vector").next();
						}
						HashMap<String, String> vuln = parseCvss(cvss.getText());
						
						//Get all vulnerable products
						String products = "";
						if (subele.contains("cpe")) {
							Element cpe = (Element) sube.elementIterator("cpe").next();
							String[] cpes = cpe.getText().split("\n");
							for (int i=0; i<cpes.length; i++) {
								if (i==cpes.length-1) {
									products = products+parseCpe(cpes[i]);
								} else {
									products = products+parseCpe(cpes[i])+" ";
								}
							}
						}
						
						if (!products.equals("")) {
							vuln.put("products", products);
						}
						
						
						Element severity;
						if (subele.contains("cvss3_base_score")) {
							severity = (Element) sube.elementIterator("cvss3_base_score").next();
						} else {
							severity = (Element) sube.elementIterator("cvss_base_score").next();
						}
						vuln.put("severity", severity.getText());
						
						
						String solution;
						if (subele.contains("solution")) {
							solution = sube.elementIterator("solution").next().getText();
						} else {
							solution = "no solution available";
						}
						//vuln.put("solution", solution);
						
						System.out.println(vuln.toString());
						fr.write(vuln.toString() + "\n");
						
						System.out.println("port number is: " + sube.attribute(0).getText());
						fr.write(sube.attribute(0).getText() + "\n");
						System.out.println("protocol is: " + sube.attribute(2).getText());
						fr.write(sube.attribute(2).getText() + "\n");
						/*System.out.println(json);
						System.out.println(host.attribute(0).getText());
						System.out.println(products);
						System.out.println(cve);
						System.out.println(cve.getText());
						System.out.println(severity.getText());
						System.out.println(solution);*/
						if(cve!=null) {
							JSONwriter(arrayd, json, host.attribute(0).getText(), products, cve.getText(), severity.getText(), solution);
						}
						
						//JSONwriter(json, host.attribute(0).getText(), products, cve.getText(), severity.getText(), solution);
					}
				}
			}
			fr.close();
			
		} 
		catch (DocumentException e) {
			e.printStackTrace();
		}
		catch (IOException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	public static HashMap<String,String> parseCvss(String vector) throws Exception {
		HashMap<String,String> res = new HashMap<>();
		String[] metrics = vector.split("/");
		String lose_types = "";
		String range = "";
		if (metrics[0].equals("CVSS:3.0")) {
			//Range
			switch(metrics[1].charAt(3)) {
			case 'P':
				range += "'physicalExploit'";
			case 'L':
				range += "'localExploit'";
				break;
			case 'A':
				range += "'adjacentExploit'";
				break;
			case 'N':
				range += "'remoteExploit'";
				break;
			default:
				range += "'other'";
			}
			
			if(metrics[4].charAt(3) == 'R') {
				range += ",'user_action_req'";
			}
			
			res.put("range", range);
			
			//Lose_type
			if(metrics[6].charAt(2)!='N') {
				lose_types += "'data_loss',";
			}
			
			if(metrics[7].charAt(2)!='N') {
				lose_types += "'data_modification',";
			}
			
			if(metrics[8].charAt(2)!='N') {
				lose_types += "'availability_loss',";
			}
			if(metrics[6].charAt(2)=='N' && metrics[7].charAt(2)=='N' && metrics[8].charAt(2)=='N') {
				lose_types += "'no_loss',";
			}
			int ltp = lose_types.length();
			lose_types = lose_types.substring(0, ltp - 1);// delete the last comma
			res.put("lose_types", lose_types);
			
			//Access
			if (metrics[2].charAt(3)=='L') {
				res.put("access", "l");
			} else {
				res.put("access", "h");
			}
			
			
		} else if (metrics[0].split("#")[0].equals("CVSS2")){
			//Range
			switch(metrics[0].charAt(9)) {
			case 'L':
				res.put("range", "'localExploit'");
				break;
			case 'A':
				res.put("range", "'adjacentExploit'");
				break;
			case 'N':
				res.put("range", "'remoteExploit'");
				break;
			}
			
			//lose_types
			if(metrics[3].charAt(2)!='N') {
				lose_types += "'data_loss',";
			}
	
			if(metrics[4].charAt(2)!='N') {
				lose_types += "'data_modification',";
			}
			
			if(metrics[5].charAt(2)!='N') {
				lose_types += "'availability_loss',";
			}
			int ltp = lose_types.length();
			lose_types = lose_types.substring(0, ltp - 1);// delete the last comma
			res.put("lose_types", lose_types);
			
			//Complexity vector
			switch(metrics[1].charAt(3)) {
			case 'L':
				res.put("access", "l");
				break;
			case 'M':
				res.put("access", "m");
				break;
			case 'H':
				res.put("access", "h");
				break;
			}
			
		} else {
			throw new Exception(vector + " is not a CVSS vector");
		}
		
		return res;
	}
	
	public static String parseCpe(String uri) throws Exception {
		String[] features = uri.split(":");
		String res = "";
		if (!features[0].equals("cpe")) {
			throw new Exception(uri + " is not a cpe URI");
		}
		
		//Find the product type
		/* Not really useful
		switch(features[1].charAt(1)) {
		case 'a':
			res+="SW:";
			break;
		case 'o':
			res+="OS:";
			break;
		case 'h':
			res+="HW:";
			break;
		}
		*/
		
		res = /*res + features[2] + " "+ */features[3];
		
		return res;
	}
	
	public static void XMLremediationConstructor(HashMap<String,String> Organization, int nbEquipments, List<String> Equipments, List<HashMap<String,String>> Countermeasures, int nbIncidents, List<HashMap<String,String>> Incidents) {
		String org_name = "";
		String org_desc = "";
		
		String id_equipments = "";
		for (int i=1; i<=nbEquipments; i++) {
			id_equipments += Integer.toString(i) + ", "; 
		}
		id_equipments = id_equipments.substring(0,id_equipments.length()-2); 
		String eq_type = "";
		
		String cm_name = "";
		String cm_desc = "";
		
		String inc_name = "";
		String inc_desc = "";
		String inc_risk_level = "";
		
		String id_countermeasure = "";
		for (int i=1; i<=nbEquipments+1; i++) {
			id_countermeasure += Integer.toString(i) + ", "; 
		}
		id_countermeasure = id_countermeasure.substring(0,id_countermeasure.length()-2);
		
		try (FileWriter fr = new FileWriter("Remediations.xml")) {
			//Racine du fichier
			fr.write("<RORI>\n");

			fr.write("<ORGANIZATIONS>\n");
			org_name = Organization.get("name");
			org_desc = Organization.get("description");
			fr.write("<organization id=\"1\" name=\"" + org_name + "\" description=\"" + org_desc + "\" id_equipments=\"" + id_equipments + "\" xpath=\"xpath\"/>\n");
			fr.write("</ORGANIZATIONS>\n");
				
			
			fr.write("<EQUIPMENTS>\n");
			for (int i=0; i<nbEquipments; i++) {
				eq_type = Equipments.get(i);
				fr.write("<equipment id=\"" + Integer.toString(i+1) + "\" name=\"E" + Integer.toString(i+1) + "\" type=\"" + eq_type + "\" AEV=\"\" xpath=\"xpath\"/>\n");
			}
			fr.write("</EQUIPMENTS>\n");
				
			 
			fr.write("<COUNTERMEASURES>\n");
			fr.write("<countermeasure id=\"1\" name=\"NOOP\" description=\"This Solution considers to accept the risk and does not require any modifications\" totally_restrictive=\"yes\" restriction=\"\" id_equipment=\"\" id_rm=\"1\" id_arc=\"1\" xpath=\"xpath\"/>\n");
			for (int i=0; i<nbEquipments; i++) {
				cm_name = Countermeasures.get(i).get("name");
				cm_desc = Countermeasures.get(i).get("description");
				fr.write("<countermeasure id=\"" + Integer.toString(i+2) + "\" name=\"" + cm_name + "\" description=\"" + cm_desc + "\" totally_restrictive=\"no\" restriction=\"1\" id_equipment=\"" + Integer.toString(i+1) + "\" id_rm=\"" + Integer.toString(i+2) + "\" id_arc=\"" + Integer.toString(i+2) + "\" xpath=\"xpath\"/>\n");
			}
			fr.write("</COUNTERMEASURES>\n");
				
			
			fr.write("<RISK_MITIGATION>\n");
			for (int i=0; i<nbEquipments+1; i++) {
				fr.write("<rm id=\"" + Integer.toString(i+1) + "\" EF=\"\" COV=\"\" RM=\"\" xpath=\"xpath\"/>\n");
			}
			fr.write("</RISK_MITIGATION>\n");
				
			
			fr.write("<ANNUAL_RESPONSE_COST>\n");
			fr.write("<arc id=\"1\" COM=\"\" COI=\"\" ODC=\"\" IC=\"\" total=\"0\" xpath=\"xpath\"/>\n");
			for (int i=0; i<nbEquipments; i++) {
				fr.write("<arc id=\"" + Integer.toString(i+2) + "\" COM=\"\" COI=\"\" ODC=\"\" IC=\"\" total=\"\" xpath=\"xpath\"/>\n");
			}
			fr.write("</ANNUAL_RESPONSE_COST>\n");
				
			
			fr.write("<INCIDENTS>\n");
			for (int i=0; i<nbIncidents; i++) {
				inc_name = Incidents.get(i).get("name");
				inc_desc = Incidents.get(i).get("description");
				inc_risk_level = Incidents.get(i).get("risk_level");
				fr.write("<incident id=\"" + Integer.toString(i+1) + "\" name=\"" + inc_name + "\" description=\"" + inc_desc + "\" risk_level=\"" + inc_risk_level + "\" id_countermeasure=\"" + id_countermeasure + "\" id_organization=\"1\" id_ale=\"1\"/>\n");
			}
			fr.write("</INCIDENTS>\n");
				
			fr.write("<ANNUAL_LOSS_EXPECTANCY>\n");
			fr.write("<ale id=\"1\" LA=\"\" LD=\"\" LR=\"\" LP=\"\" LREC=\"\" LRPC=\"\" OL=\"\" CI=\"\" ARO=\"\" total=\"\"/>\n");
			fr.write("</ANNUAL_LOSS_EXPECTANCY>\n");
				
			// fin du XML
			fr.write("</RORI>\n");
		}
		
		catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	/*public static void JSONwriter(FileWriter fr, String ip, String product, String cve, String cvss3_base_score, String countermeasure) {
		try {
			fr.write("{\n");
			fr.write("\""+"IP"+"\""+":"+"\""+ip+ "\""+",\n");
			fr.write("\""+"Product"+"\""+":" +"\""+ product +"\""+ ",\n");
			//fr.write("CVEs:[\n");
			//fr.write("{\n");
			fr.write("\""+"CVE_ID"+"\""+":" + "\""+cve+"\"" + ",\n");
			fr.write("\""+"CVSS"+"\""+":" + "\""+cvss3_base_score+"\"" + ",\n");
			fr.write("\""+"Contremesure"+"\""+":" +"\""+ countermeasure.replace("\n", "")+"\"" + "\n");
			//fr.write("},\n");
			//fr.write("],\n");
			fr.write("},\n");
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		/*JSONObject jsond = new JSONObject();
        
        jsond.put("IP", ip);
        jsond.put("Product", product);
        jsond.put("CVEs", cve);
        jsond.put("CVSS", cvss3_base_score);
        jsond.put("Countermeasure", countermeasure);
        
        System.out.println(jsond);
        try (PrintWriter out = new PrintWriter(new FileWriter(fr))) {
            out.write(jsond.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }*/
		
	//}
	public static void JSONwriter(JSONArray arrayd, String fr, String ip, String product, String cve, String cvss3_base_score, String countermeasure) {
		JSONObject jsond = new JSONObject();
		
        JSONObject counter =new JSONObject();
        
        jsond.put("IP", ip);
        jsond.put("Product", product);
        jsond.put("CVE", cve);
        jsond.put("CVSS", cvss3_base_score);
        jsond.put("Countermeasure", countermeasure.replace("\n", ""));
        arrayd.add(jsond);
        counter.put("counter", arrayd);
        //System.out.println(jsond);
        try (PrintWriter out = new PrintWriter(new FileWriter(fr))) {
            out.write(counter.toString());
            out.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
        
		
	}
	

}